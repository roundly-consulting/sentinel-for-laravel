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
- Key rings with `config` (env, the default), `database` (encrypted, integrity-bound
  envelopes) and `chain` drivers, custom drivers through `Sentinel::extend()`, SP 800-57
  statuses (pending / active / verify-only / retired / revoked) and a configured revocation
  list that beats every driver.
- `Sentinel::keys()` and the `sentinel:key:generate|rotate|revoke|retire|list` commands
  (config keys are printed as environment lines, never written to `.env`).
- The `sentinel_keys` migration (publish-only) and `KeyGenerated`, `KeyRotated`,
  `KeyRevoked`, `KeyRetired` and `KeyIntegrityViolated` events.
