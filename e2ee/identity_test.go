package e2ee

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Olace-app/olace-e2ee-go/keystore"
)

type fakeIdentityStore struct {
	getErr    error
	available bool
	values    map[string][]byte
}

func (s *fakeIdentityStore) Get(account string) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.values == nil {
		return nil, keystore.ErrNotFound
	}
	value, ok := s.values[account]
	if !ok {
		return nil, keystore.ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (s *fakeIdentityStore) Set(account string, value []byte) error {
	if s.values == nil {
		s.values = make(map[string][]byte)
	}
	s.values[account] = append([]byte(nil), value...)
	return nil
}

func (s *fakeIdentityStore) Delete(account string) error {
	delete(s.values, account)
	return nil
}

func (s *fakeIdentityStore) Available() bool {
	return s.available
}

func TestLoadIdentityV2KeepsFileWhenKeyringUnavailable(t *testing.T) {
	oldStore := identityStore
	t.Cleanup(func() { identityStore = oldStore })
	identityStore = func() keystore.Store {
		return &fakeIdentityStore{getErr: errors.New("keyring locked")}
	}

	path := filepath.Join(t.TempDir(), "identity.enc")
	key := bytes.Repeat([]byte{7}, identityWrapKeyLen)
	identity := &LocalIdentity{
		DeviceID:    "didv1_desktop",
		PublicKey:   "public",
		PrivateKey:  "private",
		Fingerprint: "fingerprint",
		KeyVersion:  1,
	}
	if err := writeEncryptedIdentityV2(path, key, identity); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	_, err := LoadEncryptedIdentity(path, "raw-device-id")
	if !errors.Is(err, ErrIdentityUnavailable) {
		t.Fatalf("expected ErrIdentityUnavailable, got %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("identity file should remain in place: %v", err)
	}
	matches, err := filepath.Glob(path + ".corrupt.*")
	if err != nil {
		t.Fatalf("glob corrupt identities: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("identity file was quarantined on transient keyring failure: %v", matches)
	}
}

func TestLoadIdentityV2QuarantinesWhenWrapKeyMissing(t *testing.T) {
	oldStore := identityStore
	t.Cleanup(func() { identityStore = oldStore })
	identityStore = func() keystore.Store {
		return &fakeIdentityStore{getErr: keystore.ErrNotFound}
	}

	path := filepath.Join(t.TempDir(), "identity.enc")
	key := bytes.Repeat([]byte{9}, identityWrapKeyLen)
	identity := &LocalIdentity{
		DeviceID:    "didv1_desktop",
		PublicKey:   "public",
		PrivateKey:  "private",
		Fingerprint: "fingerprint",
		KeyVersion:  1,
	}
	if err := writeEncryptedIdentityV2(path, key, identity); err != nil {
		t.Fatalf("write identity: %v", err)
	}

	_, err := LoadEncryptedIdentity(path, "raw-device-id")
	if !errors.Is(err, ErrIdentityCorrupted) {
		t.Fatalf("expected ErrIdentityCorrupted, got %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("identity file should be moved aside, stat err=%v", err)
	}
	matches, err := filepath.Glob(path + ".corrupt.*")
	if err != nil {
		t.Fatalf("glob corrupt identities: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one quarantined identity file, got %d: %v", len(matches), matches)
	}
}
