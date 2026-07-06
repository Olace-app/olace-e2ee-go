package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/hkdf"
)

// CryptoContext holds the session key and sequence counters for AES-GCM.
type CryptoContext struct {
	SessionID       string
	SessionKey      []byte // 32 bytes
	LocalKeyVersion int
	sendSeq         atomic.Int64
	recvSeq         atomic.Int64 // only goes up
}

// NewCryptoContext creates a CryptoContext with recvSeq initialized to -1
// so the first received frame (seq=0) passes the replay check.
func NewCryptoContext(sessionID string, sessionKey []byte, localKeyVersion int) *CryptoContext {
	c := &CryptoContext{
		SessionID:       sessionID,
		SessionKey:      sessionKey,
		LocalKeyVersion: localKeyVersion,
	}
	c.recvSeq.Store(-1)
	return c
}

// Encrypt encrypts a payload using AES-256-GCM with sequence-based AAD.
func (c *CryptoContext) Encrypt(payload map[string]any) (map[string]any, error) {
	seq := c.sendSeq.Add(1) - 1 // start from 0

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	aad := []byte(fmt.Sprintf("%s|%d|%d", c.SessionID, seq, c.LocalKeyVersion))

	cleartext, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	block, err := aes.NewCipher(c.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// GCM Seal appends the tag to the ciphertext.
	sealed := gcm.Seal(nil, nonce, cleartext, aad)
	// Split ciphertext and tag (last 16 bytes).
	ciphertext := sealed[:len(sealed)-gcm.Overhead()]
	tag := sealed[len(sealed)-gcm.Overhead():]

	return map[string]any{
		"type":               "enc",
		"v":                  1,
		"session_id":         c.SessionID,
		"seq":                seq,
		"sender_key_version": c.LocalKeyVersion,
		"nonce":              base64.StdEncoding.EncodeToString(nonce),
		"ciphertext":         base64.StdEncoding.EncodeToString(ciphertext),
		"tag":                base64.StdEncoding.EncodeToString(tag),
	}, nil
}

// Decrypt decrypts an encrypted envelope using AES-256-GCM.
func (c *CryptoContext) Decrypt(envelope map[string]any) (map[string]any, error) {
	session, _ := envelope["session_id"].(string)
	if session != c.SessionID {
		return nil, fmt.Errorf("session mismatch")
	}

	seqF, _ := envelope["seq"].(float64)
	seq := int64(seqF)
	if seq <= c.recvSeq.Load() {
		return nil, fmt.Errorf("replay detected: seq %d <= %d", seq, c.recvSeq.Load())
	}

	nonceB64, _ := envelope["nonce"].(string)
	cipherB64, _ := envelope["ciphertext"].(string)
	tagB64, _ := envelope["tag"].(string)

	if nonceB64 == "" || cipherB64 == "" || tagB64 == "" {
		return nil, fmt.Errorf("missing envelope fields")
	}

	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	tag, err := base64.StdEncoding.DecodeString(tagB64)
	if err != nil {
		return nil, fmt.Errorf("decode tag: %w", err)
	}

	senderKeyVersion := 0
	if v, ok := envelope["sender_key_version"].(float64); ok {
		senderKeyVersion = int(v)
	}
	aad := []byte(fmt.Sprintf("%s|%d|%d", c.SessionID, seq, senderKeyVersion))

	block, err := aes.NewCipher(c.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Rejoin ciphertext + tag for GCM Open.
	sealed := make([]byte, len(ciphertext)+len(tag))
	copy(sealed, ciphertext)
	copy(sealed[len(ciphertext):], tag)

	cleartext, err := gcm.Open(nil, nonce, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	c.recvSeq.Store(seq)

	var result map[string]any
	if err := json.Unmarshal(cleartext, &result); err != nil {
		return nil, fmt.Errorf("unmarshal decrypted payload: %w", err)
	}
	return result, nil
}

// --- Key derivation functions ---

// DeriveForwardSecretSessionKey derives a session key using ephemeral-only ECDH.
// Used for secure relay (via backend tunnel).
// Salt: "olace-paired-e2ee-relay-fs-v2"
func DeriveForwardSecretSessionKey(
	localEphemeralPrivate *ecdh.PrivateKey,
	remoteEphemeralPublic *ecdh.PublicKey,
	info string,
) ([]byte, error) {
	shared, err := localEphemeralPrivate.ECDH(remoteEphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("ephemeral ECDH: %w", err)
	}

	return hkdfDerive(shared, "olace-paired-e2ee-relay-fs-v2", info)
}

// DeriveSessionKey derives a session key using both static + ephemeral ECDH.
// Used for P2P LAN direct connections.
// Salt: "olace-p2p-session-v1"
func DeriveSessionKey(
	localStaticPrivate *ecdh.PrivateKey,
	remoteStaticPublic *ecdh.PublicKey,
	localEphemeralPrivate *ecdh.PrivateKey,
	remoteEphemeralPublic *ecdh.PublicKey,
	info string,
) ([]byte, error) {
	staticShared, err := localStaticPrivate.ECDH(remoteStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("static ECDH: %w", err)
	}

	ephemeralShared, err := localEphemeralPrivate.ECDH(remoteEphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("ephemeral ECDH: %w", err)
	}

	// Merge: static || ephemeral
	merged := make([]byte, len(staticShared)+len(ephemeralShared))
	copy(merged, staticShared)
	copy(merged[len(staticShared):], ephemeralShared)

	return hkdfDerive(merged, "olace-p2p-session-v1", info)
}

// DeriveAuthKey derives an HMAC auth key from static ECDH for signing hello/ack.
// Salt: "olace-p2p-auth-v1"
// Info: sorted device IDs joined by "|"
func DeriveAuthKey(
	localStaticPrivate *ecdh.PrivateKey,
	remoteStaticPublic *ecdh.PublicKey,
	localDeviceID, remoteDeviceID string,
) ([]byte, error) {
	shared, err := localStaticPrivate.ECDH(remoteStaticPublic)
	if err != nil {
		return nil, fmt.Errorf("static ECDH: %w", err)
	}

	devices := []string{localDeviceID, remoteDeviceID}
	sort.Strings(devices)
	info := strings.Join(devices, "|")

	return hkdfDerive(shared, "olace-p2p-auth-v1", info)
}

// SignTranscript HMAC-SHA256 signs a transcript with the auth key.
func SignTranscript(authKey []byte, transcript string) string {
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte(transcript))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// VerifyTranscript verifies an HMAC-SHA256 signature.
func VerifyTranscript(authKey []byte, transcript, signature string) bool {
	expected := SignTranscript(authKey, transcript)
	expectedBytes, err1 := base64.StdEncoding.DecodeString(expected)
	signatureBytes, err2 := base64.StdEncoding.DecodeString(signature)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(expectedBytes, signatureBytes)
}

// NewEphemeralKeyPair generates a new X25519 key pair.
func NewEphemeralKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// RandomBytes generates cryptographically random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

func hkdfDerive(secret []byte, salt, info string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, secret, []byte(salt), []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF derive: %w", err)
	}
	return key, nil
}
