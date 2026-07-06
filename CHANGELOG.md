# Changelog

Wire compatibility rule: any change to wire bytes (salts, transcripts,
AAD, envelope fields, key derivation) is a new minor version with a wire
compatibility note here. Never a patch release.

## v0.1.1

- Documentation: package-level security model doc, cross-platform
  machine-id wording, public-audience comments. No code behavior change.
- `GetMachineID` unexported (internal v1-fallback detail, no external
  consumers).
- CI: race detector, restricted workflow permissions.

## v0.1.0

Initial public release, extracted verbatim from the Olace daemon:
X25519 + HKDF-SHA256 + AES-256-GCM session crypto with replay
protection, canonical handshake transcripts, identity.enc v1/v2 wrap
formats with OS keystore backing, atomic file persistence, and the
shared cross-implementation test vectors.
