// Package keystore exposes a small wrapper around the OS-native keystore
// (libsecret on Linux, Keychain on macOS, wincred on Windows) used by the
// daemon to hold a single 32-byte wrap key that encrypts identity.enc.
//
// Before this package, identity.enc was encrypted with a key derived from
// /etc/machine-id (mode 444 root root, world-readable). Anyone with
// filesystem read access on both files could decrypt the static X25519
// private key on any other machine. The keystore-stored wrap key closes
// that hole on every platform that has a usable keystore session;
// environments without one (headless containers, SSH-only Linux boxes with
// no DBus session) fall back to the legacy machine-id path with a
// degraded-mode log line.
package keystore

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	keyring "github.com/zalando/go-keyring"
)

// ServiceName is the namespace under which the daemon owns all of its
// keystore entries. Stable; the OS keyring index is (service, account).
const ServiceName = "olace-daemon"

// IdentityWrapKeyAccount is the keystore account name for the 32-byte
// random key that encrypts identity.enc. Versioned so future rotations
// can land under a new account without surprise reuse.
const IdentityWrapKeyAccount = "identity-wrap-key-v1"

// ErrNotFound is returned by Get when no entry exists for the account.
var ErrNotFound = errors.New("keystore: not found")

// Store is the daemon-facing surface. Implementations MUST be safe for
// concurrent use.
type Store interface {
	Get(account string) ([]byte, error)
	Set(account string, value []byte) error
	Delete(account string) error
	// Available probes the underlying keystore once and caches the
	// result. Callers MUST fall back to a legacy key derivation when
	// this returns false.
	Available() bool
}

var defaultStore Store = &osKeyringStore{}

// Default returns the process-wide Store backed by the OS keystore.
func Default() Store { return defaultStore }

// osKeyringStore wraps zalando/go-keyring with a base64 transport layer
// (the underlying API speaks strings; we want raw bytes).
type osKeyringStore struct {
	probeOnce sync.Once
	probeOK   bool
}

func (s *osKeyringStore) Get(account string) ([]byte, error) {
	raw, err := keyring.Get(ServiceName, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keyring get: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("keyring decode: %w", err)
	}
	return decoded, nil
}

func (s *osKeyringStore) Set(account string, value []byte) error {
	encoded := base64.StdEncoding.EncodeToString(value)
	if err := keyring.Set(ServiceName, account, encoded); err != nil {
		return fmt.Errorf("keyring set: %w", err)
	}
	return nil
}

func (s *osKeyringStore) Delete(account string) error {
	err := keyring.Delete(ServiceName, account)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("keyring delete: %w", err)
}

// Available runs a best-effort write→read→delete cycle on a transient
// probe key. Cached after the first call so we don't repeatedly hit
// libsecret / Keychain / wincred during normal daemon operation.
func (s *osKeyringStore) Available() bool {
	s.probeOnce.Do(func() {
		const probeAccount = "olace-probe-keystore-available"
		probe := []byte("probe")
		if err := s.Set(probeAccount, probe); err != nil {
			return
		}
		got, err := s.Get(probeAccount)
		_ = s.Delete(probeAccount)
		if err != nil || !bytes.Equal(got, probe) {
			return
		}
		s.probeOK = true
	})
	return s.probeOK
}

// GetOrCreateRandom fetches the keystore entry under account or, if
// missing or wrong-size, generates a fresh size-byte cryptographically
// random key, stores it under account, and returns it. Wrong-size entries
// are silently overwritten (treated as corruption — the only way they
// land is if someone else wrote to the same (service, account) namespace
// or the OS keyring backend was migrated).
func GetOrCreateRandom(s Store, account string, size int) ([]byte, error) {
	if existing, err := s.Get(account); err == nil {
		if len(existing) == size {
			return existing, nil
		}
		// Wrong size — clobber and regenerate.
		_ = s.Delete(account)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	fresh := make([]byte, size)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("keystore: read random: %w", err)
	}
	if err := s.Set(account, fresh); err != nil {
		return nil, err
	}
	return fresh, nil
}
