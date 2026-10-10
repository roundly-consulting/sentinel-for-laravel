# Changelog

All notable changes to `sentinel-for-laravel` are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `AnchorPublishException`: the error a refused anchor publication reports (in
  `AnchorPublishFailed::$error`, the log line and `CheckpointResult::$anchors`).

### Security

- A checkpoint no longer overwrites an anchor that disagrees with the database. After a
  database restore, the next `sentinel:checkpoint` replaced the anchored newer checkpoint, so
  `sentinel:verify --ledger` called the rolled-back ledger intact. Now the publication is
  refused (`published: false`, `AnchorPublishFailed`, a log warning) and the anchor keeps its
  copy until someone investigates. Filesystem anchors write each `{seq}.json` only once.
- An anchor write that its store refused is reported as a failed publication. A disk with
  `throw` off (Laravel's default) or a cache store such as `null` returns false instead of
  throwing, and the checkpoint used to count that as published, with no event and no log line,
  so rollback detection looked armed while the anchor stayed empty.

## 1.0.2 - 2026-10-07

### Fixed

- On a PHP build without ext-sodium, loading an Ed25519 secret key throws
  `InvalidKeyMaterialException::unsupported` again, not `Error: Undefined constant
  "SODIUM_CRYPTO_SIGN_SECRETKEYBYTES"` (a 1.0.1 regression).

## 1.0.1 - 2026-10-05

### Changed

- Requires `roundly-consulting/crypto-for-laravel` `^1.0.1`. crypto now refuses an Ed25519 secret
  key whose public half doesn't match its seed, so sentinel drops its own sign/verify probe.
  Upgrade: `composer update roundly-consulting/crypto-for-laravel`.
- Maintenance: `composer.json` `homepage` and `support.docs` now point to the documentation site.
- Documentation: the README banner uses an absolute image URL, so it also renders on Packagist and
  other sites.

### Fixed

- A 64-byte Ed25519 secret key that isn't a real keypair is refused with "the secret key does not
  embed its own public key", not the misleading "must be the 64-byte libsodium secret key".

## 1.0.0 - 2026-10-03

Initial public release.

### Added

- The `Sentinel` facade, the injectable `SentinelManager` and one action per operation — one
  API in three styles (no global alias: import `RoundlyConsulting\Sentinel\Facades\Sentinel`).
- Canonical format `sentinel.seal/1`: RFC 8785 (JCS) documents with exact integers, typed
  and engine-portable field values (decimals at a fixed scale, datetimes as written or — with
  an offset — in UTC, never confused with each other, canonical JSON), an attribute document
  (`sentinel.seal-attributes/1`) that proves drift confined to computed values, and frozen
  known-answer vectors.
- Key material for `hmac-sha256|384|512`, `ed25519` and `ecdsa-p256-sha256|p384-sha384`
  through `crypto-for-laravel`, with the algorithm pinned per key, per-purpose HKDF subkeys
  (RFC 5869) and `base64:`-only encoding.
- `sentinel.context` configuration: an application domain separator bound into every MAC.
- Key rings with `config` (env, the default), `database` (AES-256-GCM envelopes under a key
  derived from `APP_KEY` for that purpose only, bound to their row) and `chain` drivers, custom drivers through `Sentinel::extend()`, SP 800-57
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
- `withoutSealing()` is an explicit opt-in: `sentinel.sealing.allow_suspension` ships off,
  and a key that is not set (absent, null or a blank `SENTINEL_ALLOW_SUSPENSION=`) keeps
  suspension refused (`SealingSuspensionNotAllowedException`); set it to `true` where seeders
  or imports run.
- `Sentinel::fake()`: a recording fake for application tests that keeps production
  semantics — real definitions, the tampered-write policy applied to scripted statuses
  (`fakeStatus()`, `fakeStatusOnce()`), enforced reasons and policies, and the real
  idempotency and nonce state machines in memory — with a passing-and-failing
  assertion for every operation and for its absence (36: sealing, verification,
  acknowledgement, unsealing, suspension, scans, re-sealing, keys including imports and
  retirements, checkpoints and ledger verification, idempotency, nonces, single-use URLs,
  pruning, signing and inbound signature verification) and `fakeLedgerFindings()` to script
  ledger violations.
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
- Verify-on-retrieve per seal (`verifyOnRetrieve()`, throw / report — both fire `TamperDetected` and log), the
  `sentinel.verified` route middleware (a generic 409 that reveals nothing), the
  `IntactSeal` validation rule and the `verifySeals()` collection macro.
- English and Slovak translations (`sentinel::`).
- `Idempotency-Key` support (draft-ietf-httpapi-idempotency-key-header-07): the
  `sentinel.idempotent[:required]` middleware replays a completed request's stored response
  (`Idempotent-Replayed`), answers 422 for a key reused with another payload and 409 (with
  `Retry-After`) while it is still in flight, releases the key on 5xx, never stores
  `Set-Cookie`, encrypts stored responses bound to their key and optionally commits the
  handler and the record in one transaction (database store); `Sentinel::idempotency()->run()` for jobs and commands;
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
  RFC's Appendix B test vectors. The application's own signing keys are never accepted inbound
  (`accept_signing_keys` opts in), and a ring HTTP signatures use can never vouch for a seal.
- A README covering installation, every configuration key, the threat model (what is and
  is not detected) and the full public API.
- Partner onboarding without a deploy: `Sentinel::keys()->ring('http')->import()`,
  `Sentinel::importKey()` and `sentinel:key:import` store a partner's public key (Ed25519 raw
  or SPKI PEM, ECDSA PEM) or an agreed HMAC secret in a ring's database store, bound to the
  partner model and verify-only unless imported with `signing: true`; `KeyImported` event.
- `Sentinel::signatures()->current($request)` and `->owner($request)` (also
  `Sentinel::verifiedSignature()` / `signatureOwner()`): the verified signature and the model
  owning its key.
- `sentinel:check` and `Sentinel::check()`: one health report for configuration, signing keys,
  `APP_KEY`, tables, models, anchors, checkpoint backlog, scheduling, seals on retired keys and
  stores (`--json`, `--strict`); `php artisan about` shows whether the default ring can sign
  and how the upkeep is scheduled.
- Self-scheduling upkeep (`sentinel.schedule`, `SENTINEL_SCHEDULE*`): checkpoints every
  minute, a full verify and pruning daily — each frequency configurable or `off`.
- `sentinel:verify` without arguments scans every sealable model Sentinel knows
  (`Sentinel::sealables()`: `sentinel.models`, then every class that has seals), warns about
  stored types that no longer resolve, and exits 2 when there is nothing to scan
  (`--allow-empty` accepts an empty run).
- `sentinel:install`: publishes, generates the default key when missing and prints the next
  steps.
- The `Idempotent` queue-job middleware: a job dispatched twice runs once; an in-flight
  duplicate is released back onto the queue — the running job holds its key for its
  `$timeout` (or its queue's `retry_after`, or a given `lease`).
- Idempotent runs return the JSON round-trip of the callback's result on the first run and on
  every replay; a callback whose result cannot be stored never runs a second time.
- `WithSentinelKeys` and `SentinelTestKeys::install()`: real throwaway keys for a host's test
  suite, so sealable factories seal for real.
- Scoped scans (`Sentinel::model()->scan(where: …)`), progress callbacks for scans, re-seals
  and baselines, and progress bars on the long commands.
- `Sentinel::model()->find()` / `findOrFail()` load a model with verify-on-retrieve suspended,
  for acknowledgement screens and route bindings.
- Typed middleware parameters: `VerifySeals::using()`, `EnsureIdempotency::optional()` /
  `required()` and `VerifyHttpSignature::profile()`, validated when the route is declared.
- `changedColumns()` / `changedComputed()` on verification results and tamper events, and
  `model()` on `ModelSealed`, `TamperDetected`, `TamperAcknowledged` and `SealRemoved`.
- The actions take public request objects (`SealRequest`, `VerifyRequest`,
  `VerifyManyRequest` with an optional seal; signature profiles by name), so the raw-action
  style needs no internals.
- Reading sealable models costs nothing extra unless a seal verifies on retrieve, and the
  stateless engine services are built once per request or job; a subclass may override
  `save()` / `delete()` by calling `parent::`.
- Error messages that say what to do next: the declared seals of a model, the environment
  variables of a ring without a signing key (and `WithSentinelKeys` in tests), the format of
  verify-only keys for a read-only ring.

### Upgrading from a pre-release build

- `sentinel.sealing.allow_suspension` now defaults to off. A host that calls
  `Sentinel::withoutSealing()` sets `SENTINEL_ALLOW_SUSPENSION=true` where seeders or imports
  run. A published `config/sentinel.php` keeps the old `env('SENTINEL_ALLOW_SUSPENSION', true)`
  line until you change its default to `false`.

- Migration `0004_create_sentinel_seals_table` was edited in place to add the nullable
  `attributes_mac` column; there is no new migration. A host that ran an earlier copy must
  re-publish the migrations and re-run 0004, or add the column (`string('attributes_mac', 192)->nullable()`)
  to `sentinel_seals` itself, before the next sealed write.
