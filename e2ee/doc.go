// Package e2ee is the end-to-end encryption core of Olace: the code that
// encrypts traffic between paired devices and protects the device identity
// key at rest. The Olace daemon imports this package verbatim; the Olace
// app runs a byte-compatible Dart mirror
// (github.com/Olace-app/olace-crypto-dart), and the two implementations
// are pinned to each other by the shared vectors in testdata/.
//
// # Security model
//
// Sessions come in two flavors, one cipher:
//
//   - LAN P2P (DeriveSessionKey): X25519 over both the static identity
//     keys and fresh ephemeral keys, concatenated into HKDF-SHA256 with
//     salt "olace-p2p-session-v1". Binding the static keys authenticates
//     the devices; the ephemerals freshen each session.
//   - Relay (DeriveForwardSecretSessionKey): X25519 over ephemeral keys
//     only, HKDF-SHA256 with salt "olace-paired-e2ee-relay-fs-v2".
//     Forward secret: a later identity-key compromise does not decrypt
//     recorded relay traffic. The relay server moves opaque bytes and
//     holds no key that opens them.
//
// Handshakes are authenticated by HMAC-SHA256 over a canonical transcript
// of every handshake field (handshake.go), keyed by DeriveAuthKey from the
// static-static X25519 secret. A relay that alters any field invalidates
// the signature.
//
// Frames are AES-256-GCM under one CryptoContext per session per
// direction pair: random 96-bit nonces, AAD "sessionId|seq|keyVersion",
// and a strictly increasing receive counter that rejects replays.
//
// Device identity (identity.go) is a static X25519 keypair persisted as
// identity.enc, AES-256-GCM wrapped under a random key held in the OS
// keystore, with an explicit legacy machine-id fallback for headless
// environments and quarantine-not-overwrite handling for corrupt files.
package e2ee
