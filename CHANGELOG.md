# Changelog

All notable changes to `sentinel-for-laravel` are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- Package scaffold: native service provider, configuration file and the `Sentinel` facade
  (no global alias — import `RoundlyConsulting\Sentinel\Facades\Sentinel`).
- Canonical format `sentinel.seal/1`: RFC 8785 (JCS) documents with exact integers, typed
  and engine-portable field values (decimals at a fixed scale, UTC datetimes, canonical JSON),
  and frozen known-answer vectors.
- Key material for `hmac-sha256|384|512`, `ed25519` and `ecdsa-p256-sha256|p384-sha384`
  through `crypto-for-laravel`, with the algorithm pinned per key, per-purpose HKDF subkeys
  (RFC 5869) and `base64:`-only encoding.
- `sentinel.context` configuration: an application domain separator bound into every MAC.
