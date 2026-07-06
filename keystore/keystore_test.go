package keystore

import "testing"

// The OS keyring indexes entries by (service, account). These strings are
// the on-disk identity of every wrap key written by shipped daemons: if
// either ever changes, existing installs stop finding their wrap key, v2
// identity files fail to decrypt, and the quarantine + re-enrollment path
// fires, destroying the user's paired sessions. Byte-identical, forever.
func TestKeystoreNamespaceIsFrozen(t *testing.T) {
	if ServiceName != "olace-daemon" {
		t.Fatalf("ServiceName changed to %q; this breaks every existing install", ServiceName)
	}
	if IdentityWrapKeyAccount != "identity-wrap-key-v1" {
		t.Fatalf("IdentityWrapKeyAccount changed to %q; this breaks every existing install", IdentityWrapKeyAccount)
	}
}
