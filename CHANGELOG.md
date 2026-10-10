# Changelog

All notable changes to `sentinel-for-laravel` are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## Unreleased

### Added

- `AnchorPublishException`: the error a refused anchor publication reports (in
  `AnchorPublishFailed::$error`, the log line and `CheckpointResult::$anchors`).
- `Contracts\WriteOnlyAnchor`: a marker for anchors nothing can be read back from (the built-in
  `log` anchor implements it). Implement it on a custom write-only anchor so the checkpoint run
  does not re-send it the newest checkpoint every minute.

### Changed

- Documentation: `sentinel.ledger.ring` does not follow `keys.default_ring`; a host that renames
  its default ring (`SENTINEL_DEFAULT_RING`) sets `SENTINEL_LEDGER_RING` too (config comment).

### Fixed

- `sentinel:verify --ledger` no longer reports `anchor_ahead` (and fires
  `LedgerIntegrityViolated`) when a checkpoint is committed while it walks a large ledger: the
  anchored seq is looked up in the database before it is called missing.
- A checkpoint made inside a transaction is published to the anchors only after the commit, as
  documented. An anchor used to receive it right away, so a rollback left it holding a
  checkpoint the database never had (`anchor_ahead`). `CheckpointResult::$anchors` is empty in
  that case.
- A checkpoint batch larger than the engine's bind-parameter limit (SQLite 32 766, PostgreSQL
  and MySQL 65 535) no longer fails with "too many SQL variables" on every run. `batch_size`
  allows up to 100 000, and a large `sealMissing()` baseline creates exactly such a backlog.
- `resealWhere()` and `updateAndReseal()` cover every selected row when the query has its own
  `orderBy`. They page by key, but the caller's order stayed the primary sort, so rows were
  skipped (left tampered or not updated) or handled twice.
- `increment()`, `decrement()`, `incrementEach()` and `decrementEach()` re-seal a seal that
  covers `updated_at`. Eloquent writes that timestamp in the SQL only, so the seal was left
  stale: the next verification said `Tampered (a:updated_at)` and the next `update()` was
  refused. The fake records the re-seal too.
- `Sentinel::idempotency()->run()` and the `Idempotent` job middleware no longer run a callback
  twice when its result cannot be stored after it ran (no `APP_KEY` to encrypt it, a store
  error). The key stayed `processing`, so a retry after the lease repeated the side effect; it is
  now completed as unreplayable (a repeat gets `IdempotentResponseUnavailableException`) and the
  error is rethrown.
- Rotating a config ring from an Ed25519 or ECDSA key to HMAC prints an empty
  `SENTINEL_PUBLIC_KEY=` line. Without it the old public key stayed in the environment, and the
  ring refused to load ("an HMAC key is a single secret with no public half"), so applying the
  printed lines took sealing down.
- `Sentinel::fake()`: `importKey()` refuses a key id that is taken (imported or generated under
  the fake, or held by the real key store) with `KeyDriverException`, as production does.
- `Sentinel::fake()`: `reseal()` applies `onlyOutdated`, `upgradeFormat` and `fromKeyId` as
  production does (it used to count every intact row as re-sealed), and an acknowledging run
  outside the console without an actor is refused (`AcknowledgementDeniedException`).
- Rotating a database ring demotes every key of the ring that could still sign — a pending key
  from an earlier scheduled rotation too — under row locks, so one key signs at a time. Two
  concurrent rotations, or a rotation while a scheduled key was pending, left an extra active
  key that was never demoted and could sign again later. `KeyRotated::$previousKeyId` names the
  key that was signing when the rotation committed.
- `Sentinel::fake()`: the keys it generates or imports are returned by `findKey()` and
  `listKeys()`, with their effective status (a future `activatesAt` is `pending`) and their
  owner, as production stores them. A key generated for the environment (`KeyDestination::Config`)
  is printed only, as in production — no lookup finds it.
- `Sentinel::fake()`: `rotateKey()` rotates as production does — from the key signing now (its
  algorithm by default), reporting it as `previous`; a config ring gets its environment lines
  (with the verify-only list) and the driver is `config` or `database`, never `chain`; a custom
  driver's key is refused.
- `Sentinel::fake()`: `unseal()` returns false when there was no seal to remove (already
  unsealed, never sealed, or a seal row deleted out of band), as production does; it always
  returned true.
- `Sentinel::fake()`: `sealMissing()` reports a lenient seal the fake itself unsealed instead of
  counting it as baselined — production skips any row whose ledger history shows a seal.
- `Sentinel::fake()`: `scan()` sets `truncated` when findings exceed `maxFindings`, and
  `checkSchema` refuses a sealed column the table lacks (`SealingMisconfiguredException`), as
  production does.
- `verify()`, `verifyAll()`, `isIntact()` (and the `HasSeals` helpers) on an unsaved model throw
  `SealingFailedException` ("must be persisted before it can be verified"), under the fake too,
  instead of a `TypeError`.
- `currentSeal()` returns the stored seal row with a null `sealedAt` when its `sealed_at` is
  corrupt, instead of throwing `CorruptRecordException`, so `sentinel:inspect` shows the row,
  its status (`malformed (sealed_at)`) and its history rather than aborting.
- `sentinel.idempotency.min_length` above `max_length` is refused with
  `InvalidSentinelConfigurationException` naming `idempotency.min_length`. Each bound was checked
  on its own, so the pair passed validation and every key was then refused (a 400 on every
  request).
- A `chain` ring falls back to its next store when a custom driver's signing key is on the
  revocation list (`SENTINEL_REVOKED_KEYS`), as it does for the built-in drivers. It returned
  the revoked key, and signing failed with `NoSigningKeyException`.
- `sentinel:install` generates the default ring's key with the ring's configured algorithm (it
  always used `hmac-sha256`, overriding an `ed25519` ring) and exits non-zero when generating it
  fails; it reported success while printing the error.
- Changing the primary key of a sealed row is refused with `SealingMisconfiguredException`
  (under the fake too). The write verified the new id while updating the old row: a strict seal
  threw a misleading `TamperedModelException` on an intact row, a lenient one left its seal and
  history orphaned on the old id.
- `verifyResponseSignature()` verifies a response whose body stream cannot seek (a streamed
  client response). The body was read twice; the second read was empty, so a correct signature
  failed with `digest_mismatch`. It is now read once. A non-seekable stream cannot be rewound,
  so buffer the response first if you still need its body afterwards.
- Outbound signatures take `@authority` (and `@target-uri`) from the request's `Host` header,
  as RFC 9421 defines it and as the receiver reads it. A request sent to an address with an
  explicit `Host` (`https://10.0.0.5/…` with `Host: api.example.com`) was signed for the address
  and rejected by the receiver.
- `@status` in `SigningOptions::$components`, `signatures.outbound.components` or a profile's
  `components` is refused with `InvalidSentinelConfigurationException` (RFC 9421 §2.2.9: a
  request has no status). It passed validation, then every `sign()` failed with
  `unsupported_component` and every request to such a profile was rejected; a response
  signature always covers `@status` anyway.

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
- A run with nothing pending republishes the newest checkpoint to an anchor that holds nothing
  (its first publication failed, its cache was flushed). It used to skip every empty anchor,
  so the anchor stayed empty until the next new checkpoint, and a rollback in that window went
  unseen.
- A sealed boolean stored as the text `'f'`, `'false'` (any case) no longer verifies as a sealed
  `false`. Laravel's `boolean` cast reads those strings as `true`, so a database writer could
  flip a sealed `false` (on SQLite, or any text column with a boolean cast) without detection.
  They are now refused as `not_boolean` (`Tampered(canonicalization)`); `'t'` and `'true'` still
  mean true, as they do for the cast.
- Rotating a ring whose signing key comes from a custom driver (`Sentinel::extend()`) is refused
  with `KeyDriverException`. It used to take the config path: `sentinel:key:rotate` printed the
  custom store's HMAC secret as a `PREVIOUS_KEYS` entry and dispatched `KeyRotated` for a
  rotation that never happened. That key store rotates its own keys.

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
