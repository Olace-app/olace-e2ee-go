package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/Olace-app/olace-e2ee-go/fsutil"
	"github.com/Olace-app/olace-e2ee-go/keystore"
)

// identity.enc on-disk format
// ───────────────────────────
//
//	v2:  "OLCID\x02" (6 bytes magic) || nonce(12) || ciphertext || tag(16)
//	     encrypted with a 32-byte random wrap key held in the OS keystore
//	     (libsecret / Keychain / wincred) under
//	     (service=keystore.ServiceName, account=keystore.IdentityWrapKeyAccount).
//	v1:  nonce(12) || ciphertext || tag(16)
//	     encrypted with HKDF(OS machine id, "olace-identity-v1", deviceID),
//	     where the machine id is /etc/machine-id on Linux, IOPlatformUUID
//	     on macOS, or MachineGuid on Windows.
//	     Legacy format kept readable for the one-shot v1→v2 migration that
//	     runs automatically on the first load after an upgrade. New writes
//	     only emit v2 when the keystore is reachable; v1 stays as the
//	     headless-environment fallback (containers, SSH-only boxes with
//	     no DBus session).
const (
	identityMagicV2Len = 6
	identityWrapKeyLen = 32
)

var identityMagicV2 = []byte{'O', 'L', 'C', 'I', 'D', 0x02}

// ErrIdentityCorrupted is the sentinel returned by LoadEncryptedIdentity
// when the on-disk identity.enc fails decrypt OR JSON parse. Callers can
// use errors.Is to differentiate "corrupt" from "missing" / "I/O error" /
// "permission denied" and decide whether self-heal (re-enrollment with a
// fresh keypair) is the right response. The Olace daemon falls through
// to re-enrollment on any load error, which works whether the cause was
// missing-file or corruption — this sentinel exists so callers can
// branch cleanly.
var ErrIdentityCorrupted = errors.New("identity file corrupted")

// ErrIdentityUnavailable means identity.enc is present but cannot be opened
// because an external dependency, such as the OS keyring, is temporarily
// unavailable. Callers should not rotate or quarantine the identity for this.
var ErrIdentityUnavailable = errors.New("identity temporarily unavailable")

var identityStore = keystore.Default

// LocalIdentity holds the desktop's P2P identity (X25519 key pair).
type LocalIdentity struct {
	DeviceID    string `json:"device_id"`
	PublicKey   string `json:"public_key"`  // base64
	PrivateKey  string `json:"private_key"` // base64
	Fingerprint string `json:"fingerprint"` // hex
	KeyVersion  int    `json:"key_version"`
	CreatedAt   int64  `json:"created_at"`
}

// PeerIdentity holds a remote device's public identity.
type PeerIdentity struct {
	DeviceID    string `json:"device_id"`
	PublicKey   string `json:"public_key"`  // base64
	Fingerprint string `json:"fingerprint"` // hex
	KeyVersion  int    `json:"key_version"`
}

// ToECDHPrivateKey converts the base64 private key to an ecdh.PrivateKey.
func (id *LocalIdentity) ToECDHPrivateKey() (*ecdh.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(id.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// ToECDHPublicKey converts the base64 public key to an ecdh.PublicKey.
func (id *LocalIdentity) ToECDHPublicKey() (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(id.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// ToECDHPublicKey converts a peer's base64 public key.
func (p *PeerIdentity) ToECDHPublicKey() (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode peer public key: %w", err)
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// LoadEncryptedIdentity loads and decrypts identity.enc, automatically
// detecting v1 (machine-id) vs v2 (keystore-wrapped) format from the
// 6-byte magic prefix. On a successful v1 load, if the OS keystore is
// reachable, the file is re-encrypted in place with a fresh keystore-
// stored wrap key — the user gets the security upgrade transparently
// on first daemon restart after an upgrade.
func LoadEncryptedIdentity(path, deviceID string) (*LocalIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}

	if bytes.HasPrefix(data, identityMagicV2) {
		return loadIdentityV2(path, data[identityMagicV2Len:])
	}
	return loadIdentityV1AndMaybeMigrate(path, deviceID, data)
}

func loadIdentityV2(path string, body []byte) (*LocalIdentity, error) {
	if len(body) < 12+16 {
		return nil, fmt.Errorf("identity file too short (v2)")
	}
	store := identityStore()
	key, err := store.Get(keystore.IdentityWrapKeyAccount)
	if err != nil {
		if !errors.Is(err, keystore.ErrNotFound) {
			return nil, fmt.Errorf("%w: keystore wrap key unavailable: %v", ErrIdentityUnavailable, err)
		}
		// No wrap key in the keystore + v2 ciphertext on disk = we cannot
		// recover. Quarantine and let the caller's self-heal path mint a
		// fresh keypair. This costs the user their paired sessions but
		// happens only if the user (or another process) wiped the keyring
		// entry while the daemon was down.
		quarantineCorruptIdentity(path, "keystore-missing", err)
		return nil, fmt.Errorf("%w: keystore wrap key missing: %v", ErrIdentityCorrupted, err)
	}
	if len(key) != identityWrapKeyLen {
		quarantineCorruptIdentity(path, "keystore-wrong-size", fmt.Errorf("got %d bytes", len(key)))
		return nil, fmt.Errorf("%w: keystore wrap key wrong size", ErrIdentityCorrupted)
	}
	return decryptIdentity(path, key, body, "decrypt-v2")
}

func loadIdentityV1AndMaybeMigrate(path, deviceID string, data []byte) (*LocalIdentity, error) {
	if len(data) < 12+16 {
		return nil, fmt.Errorf("identity file too short (v1)")
	}
	machineID, err := getMachineID()
	if err != nil {
		return nil, fmt.Errorf("get machine ID: %w", err)
	}
	key, err := deriveIdentityKey(machineID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("derive identity key: %w", err)
	}
	identity, err := decryptIdentity(path, key, data, "decrypt-v1")
	if err != nil {
		return nil, err
	}

	// One-shot transparent migration: now that we have the plaintext
	// identity, if the keystore is reachable, re-encrypt in place under a
	// freshly-generated wrap key. If the migration fails for any reason
	// (keystore Set rejected, disk full mid-rename) we silently stay on v1
	// — the user keeps a working daemon and the next restart retries.
	if store := identityStore(); store.Available() {
		if mErr := migrateIdentityToV2(path, store, identity); mErr != nil {
			log.Printf("identity: v1→v2 keystore migration failed (path=%s): %v (will retry next restart)", path, mErr)
		} else {
			log.Printf("identity: migrated identity.enc from machine-id (v1) to keystore-wrapped (v2)")
		}
	}
	return identity, nil
}

func decryptIdentity(path string, key, body []byte, stage string) (*LocalIdentity, error) {
	nonce := body[:12]
	ciphertext := body[12:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		quarantineCorruptIdentity(path, stage, err)
		return nil, fmt.Errorf("%w: %s: %v", ErrIdentityCorrupted, stage, err)
	}
	var identity LocalIdentity
	if err := json.Unmarshal(plaintext, &identity); err != nil {
		quarantineCorruptIdentity(path, "parse", err)
		return nil, fmt.Errorf("%w: parse identity: %v", ErrIdentityCorrupted, err)
	}
	return &identity, nil
}

func migrateIdentityToV2(path string, store keystore.Store, identity *LocalIdentity) error {
	key, err := keystore.GetOrCreateRandom(store, keystore.IdentityWrapKeyAccount, identityWrapKeyLen)
	if err != nil {
		return fmt.Errorf("ensure wrap key: %w", err)
	}
	return writeEncryptedIdentityV2(path, key, identity)
}

// quarantineCorruptIdentity renames a corrupt identity file to
// <path>.corrupt.<unix-timestamp> so the user can inspect what was on
// disk before the caller's self-heal path (fresh keypair enrollment,
// in the Olace daemon) overwrites it. Best-effort:
// rename failure is logged but not fatal — self-heal still proceeds and
// will overwrite the corrupt file in place via fsutil.WriteFileAtomic.
func quarantineCorruptIdentity(path, stage string, cause error) {
	quarantinePath := fmt.Sprintf("%s.corrupt.%d", path, time.Now().Unix())
	if rerr := os.Rename(path, quarantinePath); rerr != nil {
		log.Printf("identity: quarantine rename failed (path=%s stage=%s): %v (original cause: %v)", path, stage, rerr, cause)
		return
	}
	log.Printf("identity: corrupt identity.enc quarantined to %s (stage=%s, cause: %v); daemon will self-heal via fresh keypair", quarantinePath, stage, cause)
}

// getMachineID reads the platform-specific machine identifier used by
// the legacy v1 key derivation: /etc/machine-id on Linux, IOPlatformUUID
// on macOS, MachineGuid on Windows.
func getMachineID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			return "", fmt.Errorf("read /etc/machine-id: %w", err)
		}
		return strings.TrimSpace(string(data)), nil

	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", fmt.Errorf("run ioreg: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					uuid := strings.TrimSpace(parts[1])
					uuid = strings.Trim(uuid, "\"")
					return uuid, nil
				}
			}
		}
		return "", fmt.Errorf("IOPlatformUUID not found")

	case "windows":
		out, err := exec.Command("reg", "query",
			`HKLM\SOFTWARE\Microsoft\Cryptography`,
			"/v", "MachineGuid").Output()
		if err != nil {
			return "", fmt.Errorf("query registry: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "MachineGuid") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					return fields[len(fields)-1], nil
				}
			}
		}
		return "", fmt.Errorf("MachineGuid not found")

	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// deriveIdentityKey derives the encryption key from machine ID and device ID.
func deriveIdentityKey(machineID, deviceID string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, []byte(machineID), []byte("olace-identity-v1"), []byte(deviceID))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateIdentity creates a fresh X25519 keypair as a LocalIdentity with
// no device metadata attached. Callers own registration and persistence:
// fill in DeviceID / Fingerprint / KeyVersion from the registry of record,
// then persist with SaveEncryptedIdentity.
func GenerateIdentity() (*LocalIdentity, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}
	pub := priv.PublicKey()
	return &LocalIdentity{
		PublicKey:  base64.StdEncoding.EncodeToString(pub.Bytes()),
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		CreatedAt:  time.Now().UnixMilli(),
	}, nil
}

// SaveEncryptedIdentity writes identity to path, preferring the v2
// (keystore-wrapped) format. Falls back to v1 (machine-id) only when the
// OS keystore probe fails — that's the "degraded but functional" path
// for headless containers / SSH-only Linux without DBus.
func SaveEncryptedIdentity(path, deviceID string, identity *LocalIdentity) error {
	if store := identityStore(); store.Available() {
		key, err := keystore.GetOrCreateRandom(store, keystore.IdentityWrapKeyAccount, identityWrapKeyLen)
		if err != nil {
			return fmt.Errorf("keystore wrap key: %w", err)
		}
		return writeEncryptedIdentityV2(path, key, identity)
	}
	log.Printf("identity: keystore unavailable — falling back to machine-id encryption (degraded mode)")
	return writeEncryptedIdentityV1(path, deviceID, identity)
}

func writeEncryptedIdentityV2(path string, wrapKey []byte, identity *LocalIdentity) error {
	body, err := encryptIdentityBody(wrapKey, identity)
	if err != nil {
		return err
	}
	data := make([]byte, 0, identityMagicV2Len+len(body))
	data = append(data, identityMagicV2...)
	data = append(data, body...)
	return writeIdentityFile(path, data)
}

func writeEncryptedIdentityV1(path, deviceID string, identity *LocalIdentity) error {
	machineID, err := getMachineID()
	if err != nil {
		return err
	}
	key, err := deriveIdentityKey(machineID, deviceID)
	if err != nil {
		return err
	}
	body, err := encryptIdentityBody(key, identity)
	if err != nil {
		return err
	}
	return writeIdentityFile(path, body)
}

func encryptIdentityBody(key []byte, identity *LocalIdentity) ([]byte, error) {
	plaintext, err := json.Marshal(identity)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func writeIdentityFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	// Atomic write — a partial write here would leave an undecryptable
	// identity on disk, locking the user out of their paired-peer sessions.
	return fsutil.WriteFileAtomic(path, data, 0600)
}

// ParsePeerIdentity parses a peer identity from a raw JSON map.
func ParsePeerIdentity(raw map[string]any) (*PeerIdentity, error) {
	deviceID, _ := raw["device_id"].(string)
	publicKey, _ := raw["public_key"].(string)
	fingerprint, _ := raw["fingerprint"].(string)
	keyVersionF, _ := raw["key_version"].(float64)
	keyVersion := int(keyVersionF)

	if deviceID == "" || publicKey == "" || fingerprint == "" || keyVersion <= 0 {
		return nil, fmt.Errorf("invalid peer identity")
	}

	return &PeerIdentity{
		DeviceID:    strings.TrimSpace(deviceID),
		PublicKey:   strings.TrimSpace(publicKey),
		Fingerprint: strings.TrimSpace(fingerprint),
		KeyVersion:  keyVersion,
	}, nil
}
