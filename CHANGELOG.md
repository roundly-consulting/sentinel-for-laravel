# Changelog

All notable changes to `sentinel-for-laravel` are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

Initial public release.

### Added

- The `Sentinel` facade, the injectable `SentinelManager` and one action per operation — one
  API in three styles (no global alias: import `RoundlyConsulting\Sentinel\Facades\Sentinel`).
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
- Tamper-evident seals on Eloquent models: declare named seals in `defineSeals()` (typed
  attributes, computed values, tenant scope, rings, algorithms, strict/lenient, reusable
  `SealDefinition` classes), compiled once and validated with every problem listed.
- Atomic sealing on every Eloquent write path (save, update, create, touch, push, restore,
  increment/decrement, delete, force delete and their quiet variants): the row is read back
  under a lock and the seal written in the same transaction, so a sealing failure rolls the
  write back.
- Verification with a structured `VerificationResult` (intact, outdated, unsealed, tampered,
  missing, stale, unknown/revoked/retired key, algorithm not allowed/mismatch, malformed,
  unverifiable) and the changed attribute names; `TamperDetected` events and log lines.
- Writes to a model changed outside the application are refused by default
  (`sentinel.sealing.on_tampered_write`); `acknowledge()` accepts the change with a required
  reason, a recorded actor and an optional Gate ability.
- An append-only, MAC'd ledger of every seal event (seal, re-seal, acknowledgement, deletion,
  unseal) that detects replayed and rolled-back seals.
- `Sentinel::for($model)`, `Sentinel::model(Invoice::class)`, `withoutSealing()`,
  `withoutVerification()` and the `HasSeals` trait helpers and scopes.
- `Sentinel::fake()`: a recording fake for application tests that keeps production
  semantics — real definitions, the tampered-write policy applied to scripted statuses
  (`fakeStatus()`, `fakeStatusOnce()`), enforced reasons and policies, and the real
  idempotency and nonce state machines in memory — with an assertion for every operation
  (sealing, verification, acknowledgement, keys, checkpoints, re-sealing, idempotency, nonces,
  signed requests).
- Keyed, chained ledger checkpoints (`sentinel:checkpoint`, `Sentinel::ledger()->checkpoint()`)
  published to external anchors (`cache`, `filesystem`, `log`, or custom ones through
  `Sentinel::extendAnchor()`), so deleted, rewritten or rolled-back ledger history — and,
  with an anchor, a restore of the whole database — is detectable.
- Ledger verification (`Sentinel::ledger()->verify()`, `sentinel:verify --ledger`): checkpoint
  sequence, chain, MACs and roots, anchors, pending entries, a stalled checkpoint job and
  every entity's ledger head; violations fire `LedgerIntegrityViolated`.
- `sentinel:verify` (chunked scans for cron and CI, JSON output, `--fail-on`, exit 1 on
  findings), `sentinel:reseal` (rotation that never launders), `sentinel:seal-missing`
  (baseline adoption) and `sentinel:inspect`.
- `Sentinel::model(Invoice::class)->scan()`, `reseal()`, `resealWhere()` (bulk
  acknowledgement), `updateAndReseal()` (a verified mass update) and `sealMissing()`.
- Verify-on-retrieve per seal (`verifyOnRetrieve()`, throw / event / log), the
  `sentinel.verified` route middleware (a generic 409 that reveals nothing), the
  `IntactSeal` validation rule and the `verifySeals()` collection macro.
- English and Slovak translations (`sentinel::`).
- `Idempotency-Key` support (draft-ietf-httpapi-idempotency-key-header-07): the
  `sentinel.idempotent[:required]` middleware replays a completed request's stored response
  (`Idempotent-Replayed`), answers 422 for a key reused with another payload and 409 (with
  `Retry-After`) while it is still in flight, releases the key on 5xx, never stores
  `Set-Cookie`, encrypts stored responses and optionally commits the handler and the record
  in one transaction; `Sentinel::idempotency()->run()` for jobs and commands;
  `Http::withIdempotencyKey()` for outgoing requests; database and cache stores (an edited
  stored record fails closed in both).
- Single-use, purpose-bound nonces (`Sentinel::nonces()->issue()/consume()`, only digests
  stored, atomic consume) and single-use signed URLs (`signedRoute()` + the
  `sentinel.single-use` middleware); `sentinel:prune` for expired keys and nonces.
- RFC 9457 problem responses for every HTTP rejection, and an RFC 9651 structured-field
  parser and serializer.
- RFC 9421 HTTP message signatures: the `sentinel.signed[:profile]` middleware verifies
  `hmac-sha256`, `ed25519`, `ecdsa-p256-sha256` and `ecdsa-p384-sha384` signatures (keys of
  a dedicated ring, the algorithm taken from the key, a clock-skew window, RFC 9530
  `Content-Digest`, nonce replay protection) and answers 401 problem details with an
  `Accept-Signature` hint; `Http::withSignature()` signs outgoing requests;
  `Sentinel::signatures()->verifyResponse()` checks signed responses. Verified against the
  RFC's Appendix B test vectors.
- A README covering installation, every configuration key, the threat model (what is and
  is not detected) and the full public API.
