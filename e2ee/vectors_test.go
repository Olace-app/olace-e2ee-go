package e2ee

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectors_test pins this implementation to testdata/e2ee_vectors.json, the
// shared cross-implementation vectors also enforced against the Dart mirror
// (olace-crypto-dart). A failure here means wire bytes changed: that is
// never a refactor, it is a protocol break.

type vectorsFile struct {
	X25519 struct {
		AliceScalarHex string `json:"alice_scalar_hex"`
		AlicePublicHex string `json:"alice_public_hex"`
		BobScalarHex   string `json:"bob_scalar_hex"`
		BobPublicHex   string `json:"bob_public_hex"`
		EphAScalarHex  string `json:"eph_a_scalar_hex"`
		EphAPublicHex  string `json:"eph_a_public_hex"`
		EphBScalarHex  string `json:"eph_b_scalar_hex"`
		EphBPublicHex  string `json:"eph_b_public_hex"`
		SharedHex      string `json:"shared_alice_bob_hex"`
	} `json:"x25519"`
	Fields      map[string]any `json:"fields"`
	Transcripts struct {
		P2PHello       transcriptVector `json:"p2p_hello"`
		P2PAck         transcriptVector `json:"p2p_ack"`
		RelayHello     transcriptVector `json:"relay_hello"`
		RelayAck       transcriptVector `json:"relay_ack"`
		P2PSessionInfo string           `json:"p2p_session_info"`
		RelayFsInfo    string           `json:"relay_fs_info"`
	} `json:"transcripts"`
	DerivedKeys struct {
		AuthKeyHex       string `json:"auth_key_hex"`
		P2PSessionKeyHex string `json:"p2p_session_key_hex"`
		RelayFsKeyHex    string `json:"relay_fs_key_hex"`
	} `json:"derived_keys"`
	Fingerprint struct {
		PublicKeyB64   string `json:"public_key_b64"`
		FingerprintHex string `json:"fingerprint_hex"`
	} `json:"fingerprint"`
	Envelopes []struct {
		Name          string         `json:"name"`
		SessionKeyHex string         `json:"session_key_hex"`
		Envelope      map[string]any `json:"envelope"`
		PlaintextJSON string         `json:"plaintext_json"`
	} `json:"envelopes"`
}

type transcriptVector struct {
	Transcript string `json:"transcript"`
	HmacB64    string `json:"hmac_b64"`
}

func loadVectors(t *testing.T) *vectorsFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/e2ee_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func vecPriv(t *testing.T, scalarHex string) *ecdh.PrivateKey {
	t.Helper()
	raw, err := hex.DecodeString(scalarHex)
	if err != nil {
		t.Fatalf("decode scalar: %v", err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("new private key: %v", err)
	}
	return k
}

func TestVectorsX25519(t *testing.T) {
	v := loadVectors(t)
	// Alice/Bob are the RFC 7748 section 6.1 keys; this doubles as a
	// known-answer test against the RFC, not just self-consistency.
	alice := vecPriv(t, v.X25519.AliceScalarHex)
	bob := vecPriv(t, v.X25519.BobScalarHex)
	if got := hex.EncodeToString(alice.PublicKey().Bytes()); got != v.X25519.AlicePublicHex {
		t.Fatalf("alice public mismatch: %s", got)
	}
	if got := hex.EncodeToString(bob.PublicKey().Bytes()); got != v.X25519.BobPublicHex {
		t.Fatalf("bob public mismatch: %s", got)
	}
	shared, err := alice.ECDH(bob.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(shared); got != v.X25519.SharedHex {
		t.Fatalf("shared secret mismatch: %s", got)
	}
}

func TestVectorsTranscriptsAndKeys(t *testing.T) {
	v := loadVectors(t)
	f := v.Fields
	str := func(k string) string { return f[k].(string) }
	num := func(k string) int { return int(f[k].(float64)) }

	alice := vecPriv(t, v.X25519.AliceScalarHex)
	bob := vecPriv(t, v.X25519.BobScalarHex)
	ephA := vecPriv(t, v.X25519.EphAScalarHex)
	ephB := vecPriv(t, v.X25519.EphBScalarHex)

	hello := BuildP2PHelloTranscript(
		str("ticket"), str("pair_id"), str("user_id"), str("mobile_device_id"), str("desktop_device_id"),
		num("mobile_key_version"), num("desktop_key_version"),
		str("session_id"), str("client_eph_pub_b64"), str("client_nonce"))
	if hello != v.Transcripts.P2PHello.Transcript {
		t.Fatalf("p2p hello transcript mismatch:\n got %s\nwant %s", hello, v.Transcripts.P2PHello.Transcript)
	}
	ack := BuildP2PAckTranscript(
		str("ticket"), str("pair_id"), str("user_id"), str("mobile_device_id"), str("desktop_device_id"),
		num("mobile_key_version"), num("desktop_key_version"),
		str("session_id"), str("client_eph_pub_b64"), str("server_eph_pub_b64"), str("client_nonce"), str("server_nonce"))
	if ack != v.Transcripts.P2PAck.Transcript {
		t.Fatalf("p2p ack transcript mismatch: %s", ack)
	}
	relayHello := BuildSecureRelayHelloTranscript(
		str("pair_id"), str("user_id"), str("mobile_device_id"), str("desktop_device_id"),
		num("mobile_key_version"), num("desktop_key_version"),
		str("session_id"), str("server_eph_pub_b64"), str("server_nonce"))
	if relayHello != v.Transcripts.RelayHello.Transcript {
		t.Fatalf("relay hello transcript mismatch: %s", relayHello)
	}
	relayAck := BuildSecureRelayAckTranscript(
		str("pair_id"), str("user_id"), str("mobile_device_id"), str("desktop_device_id"),
		num("mobile_key_version"), num("desktop_key_version"),
		str("session_id"), str("server_eph_pub_b64"), str("client_eph_pub_b64"), str("server_nonce"), str("client_nonce"))
	if relayAck != v.Transcripts.RelayAck.Transcript {
		t.Fatalf("relay ack transcript mismatch: %s", relayAck)
	}

	authKey, err := DeriveAuthKey(alice, bob.PublicKey(), str("mobile_device_id"), str("desktop_device_id"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(authKey); got != v.DerivedKeys.AuthKeyHex {
		t.Fatalf("auth key mismatch: %s", got)
	}
	for name, tv := range map[string]transcriptVector{
		"p2p_hello":   v.Transcripts.P2PHello,
		"p2p_ack":     v.Transcripts.P2PAck,
		"relay_hello": v.Transcripts.RelayHello,
		"relay_ack":   v.Transcripts.RelayAck,
	} {
		if got := SignTranscript(authKey, tv.Transcript); got != tv.HmacB64 {
			t.Fatalf("%s hmac mismatch: %s", name, got)
		}
		if !VerifyTranscript(authKey, tv.Transcript, tv.HmacB64) {
			t.Fatalf("%s hmac does not verify", name)
		}
	}

	p2pKey, err := DeriveSessionKey(alice, bob.PublicKey(), ephA, ephB.PublicKey(), v.Transcripts.P2PSessionInfo)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(p2pKey); got != v.DerivedKeys.P2PSessionKeyHex {
		t.Fatalf("p2p session key mismatch: %s", got)
	}
	fsKey, err := DeriveForwardSecretSessionKey(ephA, ephB.PublicKey(), v.Transcripts.RelayFsInfo)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(fsKey); got != v.DerivedKeys.RelayFsKeyHex {
		t.Fatalf("relay fs key mismatch: %s", got)
	}
}

func TestVectorsEnvelopeDecrypt(t *testing.T) {
	v := loadVectors(t)
	sessionID := v.Fields["session_id"].(string)
	for _, ev := range v.Envelopes {
		key, err := hex.DecodeString(ev.SessionKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		ctx := NewCryptoContext(sessionID, key, 1)
		got, err := ctx.Decrypt(ev.Envelope)
		if err != nil {
			t.Fatalf("%s: decrypt failed: %v", ev.Name, err)
		}
		var want map[string]any
		if err := json.Unmarshal([]byte(ev.PlaintextJSON), &want); err != nil {
			t.Fatal(err)
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if string(gotJSON) != string(wantJSON) {
			t.Fatalf("%s: plaintext mismatch:\n got %s\nwant %s", ev.Name, gotJSON, wantJSON)
		}
		// Replay of the same seq must now be rejected.
		if _, err := ctx.Decrypt(ev.Envelope); err == nil {
			t.Fatalf("%s: replayed envelope accepted", ev.Name)
		}
	}
}
