# olace-e2ee-go

The end-to-end encryption core of [Olace](https://olace.app). This module contains the code that encrypts data between paired Olace devices before it touches any network, and the code that protects the device identity key at rest. The Olace daemon imports this module verbatim; what you audit here is what ships.

## What is in this repo

- `e2ee/crypto.go`: session cryptography. X25519 key agreement, HKDF-SHA256 key derivation, AES-256-GCM framing with sequence-based AAD and replay protection, HMAC-SHA256 transcript signing.
- `e2ee/handshake.go`: canonical handshake transcripts for the two session types, LAN P2P (`olace-p2p-session-v1`) and secure relay over the Olace backend tunnel (`olace-paired-e2ee-relay-fs-v2`, ephemeral-only, forward secret). The backend relays opaque ciphertext; session keys are derived only on the two devices.
- `e2ee/identity.go`: the device identity keypair and its at-rest protection (`identity.enc`). v2 format wraps the key with a random 32-byte key held in the OS keystore (libsecret, Keychain, wincred); v1 is a legacy machine-id fallback for headless environments, migrated to v2 automatically when a keystore is available.
- `keystore/`: the OS keystore wrapper holding the identity wrap key.
- `fsutil/`: atomic file writes and file locks used for key material persistence.
- `cmd/genvectors` and `e2ee/testdata/`: the generator and the committed cross-implementation test vectors. Both this repo and the Dart mirror enforce the same vector file in CI, so the two implementations cannot drift apart silently.

The same cryptography is mirrored client-side in Dart: [olace-crypto-dart](https://github.com/Olace-app/olace-crypto-dart). Both implementations are pinned to each other by shared test vectors in [transparency](https://github.com/Olace-app/transparency).

## What is intentionally not in this repo

Session orchestration (reconnects, stream routing, metrics), backend registration of public identity keys, and the rest of the Olace daemon are closed source. They consume this module through its exported API and never touch key derivation or ciphertext framing themselves. The full design, including what Olace servers store and what they cannot read, is documented in the [transparency](https://github.com/Olace-app/transparency) repo.

## Versioning

v0.x until Olace launch. Any change to wire bytes (salts, transcripts, AAD, envelope fields) is a new minor version with a wire compatibility note in [CHANGELOG.md](CHANGELOG.md), never a patch release.

## Security

See [SECURITY.md](SECURITY.md). Report vulnerabilities to security@olace.app.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
