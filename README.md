<!-- roundly-hero:start -->
<p align="center">
  <a href="https://roundly-consulting.com/open-source/docs/sentinel-for-laravel?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel">
    <img src="art/hero.png" alt="Sentinel for Laravel — Roundly open source" width="100%">
  </a>
</p>
<!-- roundly-hero:end -->

<!-- roundly-badges:start -->
<p align="center">
  <a href="https://packagist.org/packages/roundly-consulting/sentinel-for-laravel"><img src="https://img.shields.io/packagist/v/roundly-consulting/sentinel-for-laravel?style=flat-square&label=release" alt="Latest release"></a>
  <a href="https://github.com/roundly-consulting/sentinel-for-laravel/actions/workflows/run-tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/sentinel-for-laravel/run-tests.yml?branch=main&style=flat-square&label=tests" alt="Tests"></a>
  <a href="https://github.com/roundly-consulting/sentinel-for-laravel/actions/workflows/fix-php-code-style-issues.yml"><img src="https://img.shields.io/github/actions/workflow/status/roundly-consulting/sentinel-for-laravel/fix-php-code-style-issues.yml?branch=main&style=flat-square&label=code%20style" alt="Code style"></a>
  <a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/donate-support%20our%20open%20source-F24E29?style=flat-square&logo=stripe&logoColor=white" alt="Donate"></a>
  <a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/patreon-become%20a%20patron-F96854?style=flat-square&logo=patreon&logoColor=white" alt="Patreon"></a>
  <a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel#crypto"><img src="https://img.shields.io/badge/crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=flat-square&logo=bitcoin&logoColor=white" alt="Crypto"></a>
</p>
<!-- roundly-badges:end -->

# Sentinel for Laravel

Know when your data was changed behind your application's back, and make every request
count once. Sentinel seals Eloquent models with keyed MACs or signatures, detects any change
made outside the application (a SQL console, a mass `update()`, a restored backup), and adds
the request-integrity tools around it: idempotency keys, single-use nonces and URLs, and
RFC 9421 HTTP message signatures.

- **Seals** — named, typed seals declared on the model, written atomically with every
  Eloquent write, verified anywhere (API, middleware, validation rule, collection, retrieve,
  console scan). Writes to a tampered row are refused until someone acknowledges the change
  with a reason.
- **Ledger** — an append-only, MAC'd history of every seal event, folded into chained
  checkpoints and optionally published to external anchors, so deleted or rolled-back
  history is detectable.
- **Keys** — HMAC-SHA-256/384/512, Ed25519 and ECDSA P-256/P-384 keys in named rings, from
  the environment or encrypted database rows, with rotation, revocation and retirement.
- **Requests** — `Idempotency-Key` handling, nonces, single-use signed URLs and HTTP message
  signatures in and out.

Built only on Laravel and three Roundly Tier-0 packages (`package-toolkit`, `enums`,
`crypto`).

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [What it detects (threat model)](#what-it-detects-threat-model)
- [Configuration](#configuration)
- [Declaring seals](#declaring-seals)
- [Sealing and writes](#sealing-and-writes)
- [Verifying](#verifying)
- [Acknowledging out-of-band changes](#acknowledging-out-of-band-changes)
- [Bulk operations](#bulk-operations)
- [Ledger, checkpoints and anchors](#ledger-checkpoints-and-anchors)
- [Middleware, validation rule, collection macro and scopes](#middleware-validation-rule-collection-macro-and-scopes)
- [Idempotency keys](#idempotency-keys)
- [Nonces and single-use URLs](#nonces-and-single-use-urls)
- [HTTP message signatures](#http-message-signatures)
- [Key management](#key-management)
- [Commands and scheduling](#commands-and-scheduling)
- [Events](#events)
- [Extending](#extending)
- [Without the facade](#without-the-facade)
- [Testing your application](#testing-your-application)
- [Naming](#naming)

## Requirements

- PHP 8.4+ with `ext-hash` and `ext-mbstring`; `ext-sodium` for `ed25519` keys
- Laravel 12.x or 13.x
- SQLite, PostgreSQL or MySQL (every table and every race is tested on all three engines)

## Installation

```bash
composer require roundly-consulting/sentinel-for-laravel
```

Publish and run the migrations (six tables, all prefixed `sentinel_`):

```bash
php artisan vendor:publish --tag="sentinel-migrations"
php artisan migrate
```

Optionally publish the configuration file and the translations (English and Slovak):

```bash
php artisan vendor:publish --tag="sentinel-config"
php artisan vendor:publish --tag="sentinel-translations"
```

Generate the key of the default ring. It is printed as environment lines — add them to
`.env` and treat them as secrets; the command never writes `.env` itself:

```bash
php artisan sentinel:key:generate
# SENTINEL_KEY_ID=default-20261002-k3f9qa
# SENTINEL_ALGORITHM=hmac-sha256
# SENTINEL_KEY="base64:…"
```

Set `sentinel.key_type` (and `sentinel.actor_key_type`) to `uuid` or `ulid` **before**
migrating if your sealed models (or your users) use those keys.

## Quick start

Declare a seal on the model:

```php
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;

final class Invoice extends Model implements Sealable
{
    use HasSeals;

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('financial')->attributes('customer_id', 'currency', 'amount', 'status');
    }
}
```

Every Eloquent write now seals the row. Rows that existed before get a baseline once:

```bash
php artisan sentinel:seal-missing "App\Models\Invoice" --reason="Initial baseline"
```

Verify wherever it matters:

```php
use RoundlyConsulting\Sentinel\Facades\Sentinel;

$invoice->isIntact();                          // true when every seal verifies
Sentinel::for($invoice)->verifyOrFail();       // throws TamperedModelException otherwise

Route::get('/invoices/{invoice}', ShowInvoice::class)->middleware('sentinel.verified');
```

Someone runs `UPDATE invoices SET amount = 0 WHERE id = 42` in a SQL console:

```php
Sentinel::for($invoice)->verify();
// VerificationResult { status: Tampered, reason: 'mac', changedAttributes: ['a:amount'], … }

$invoice->update(['note' => 'x']);             // TamperedModelException: refused until acknowledged

Sentinel::for($invoice)->by($admin)->because('INC-88: refund fixed by the DBA')->acknowledge();
```

Schedule the ledger checkpoints and a nightly scan (`routes/console.php`):

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('sentinel:checkpoint')->everyMinute();
Schedule::command('sentinel:verify --ledger')->hourly();
```

## What it detects (threat model)

Sentinel **detects**; database grants and row-level security **prevent**. The two complement
each other.

### Actors

| Id | Actor | Capabilities | In scope |
|---|---|---|---|
| A1 | **DB writer** | `INSERT/UPDATE/DELETE` on any table incl. `sentinel_*`; no code execution; no access to env/config/`APP_KEY` | yes |
| A2 | **DB writer + snapshot restore** | A1 + replace tables or the whole database with an older snapshot | yes (needs anchors for full coverage) |
| A3 | **Network/client attacker** | replays, alters or duplicates HTTP requests | yes |
| A4 | **Authorised insider** | uses the app normally (e.g. acknowledges changes) | audited (actor + reason + changed attributes in the MAC'd ledger); authorisation is the host's job (Gate hook) |
| A5 | holder of signing keys / `APP_KEY` (database-driver keys) / RCE / config write | can forge anything | out of scope |

### Detection matrix

"Window" means the time since the last checkpoint (default: scheduled every minute).

| # | Attack | DB-only (no anchor) | With ≥ 1 external anchor | Status / finding |
|---|---|---|---|---|
| 1 | Change a sealed column | yes | yes | `Tampered` (+ changed attributes via field tags) |
| 2 | Change rows feeding a computed value | yes | yes | `Tampered` |
| 3 | Copy values + seal from another row / model / seal name / tenant scope / app context | yes (domain separation) | yes | `Tampered` |
| 4 | Re-point a seal row (`sealable_id`, `seal`) | yes | yes | `Tampered` |
| 5 | Delete a seal row | yes | yes | `Missing` (`seal_deleted` when ledger history exists) |
| 6 | Insert an unsealed row (strict seal) | yes | yes | `Missing` (`never_sealed`); a lenient seal → `Unsealed` (by definition not a finding) |
| 7 | Restore an older row + its older seal row | yes, while the newer ledger entries exist | yes | `Stale` (`newer_version`) |
| 8 | #7 + delete the newer ledger entries | yes if those entries were already checkpointed (`CheckpointMismatch`); no inside the window | yes outside the window | ledger findings |
| 9 | Restore the **whole** database (incl. ledger + checkpoints) to an older snapshot | no | yes (`AnchorAhead`) for any rollback past the last anchored checkpoint | ledger finding |
| 10 | Delete the checkpoint tail (+ entries) | no | yes | `AnchorAhead` |
| 11 | Rewrite a ledger entry or checkpoint | yes (entry MAC / checkpoint MAC + chain) | yes | `EntryInvalid`, `CheckpointInvalid`, `ChainBroken` |
| 12 | Delete a sealable row without a tombstone | yes (`sentinel:verify --ledger`: live ledger head, row gone) | yes | `EntityDeleted` |
| 13 | Rewrite the stored `algorithm` / `key_id` / `ring` on a seal row | yes (the algorithm comes from the key; ring allow-list; HKDF info binds ring + kid + algorithm) | yes | `AlgorithmMismatch` / `UnknownKey` / `Tampered` |
| 14 | Database-driver key rows: swap ring/kid/algorithm, replace a public key | yes (encrypted, MAC'd envelope binds every field) | yes | `KeyIntegrityException` → `UnknownKey` |
| 15 | Database-driver key rows: restore an older envelope (un-revoke a key) | no (an authentic old ciphertext) — mitigation: list the kid in `SENTINEL_REVOKED_KEYS`, which always wins | no | — |
| 16 | Changes made **and** rolled back entirely inside the window | no | no | — (shorten the checkpoint interval) |
| 17 | Replay a signed HTTP request | yes (`created`/`expires` window + nonce de-duplication) | — | `replayed`, `too_old`, `expired` |
| 18 | Alter the body/headers of a signed request | yes (`content-digest` + signature) | — | `digest_mismatch`, `invalid_signature` |
| 19 | Duplicate a POST (retry storm, double click) | yes (replay / 409) | — | idempotency |
| 20 | Reuse an idempotency key with another payload | yes (422) | — | idempotency |
| 21 | Reuse a single-use URL | yes (atomic consume) | — | 403 |

### What it does not guarantee

- Sentinel detects; it does not prevent. A row may be tampered with between two
  verifications.
- Rows written through the query builder, raw SQL or `withoutSealing()` are unsealed or stale
  until re-sealed. Strict seals report them.
- Database-driver keys are only as safe as `APP_KEY`. The `config` driver keeps keys out of
  the database (recommended for the default ring).
- Without an external anchor, a full-database rollback (#9) and checkpoint truncation (#10)
  are undetectable.
- Verification proves integrity relative to the last authorised seal, **not** that the
  authorised value was correct.
- Computed values that read related rows are only as fresh as the last re-seal of the owning
  model.

Out of scope by design: confidentiality (use Laravel's `encrypted` casts), an attacker holding
the signing keys, `APP_KEY` (for database-driver keys), the deployed code or the
configuration, and intercepting query-builder or raw SQL writes (they are detected
afterwards).

## Configuration

The published `config/sentinel.php` documents every key. All of them:

| Key | Type | Default | Env | Purpose |
|---|---|---|---|---|
| `context` | string | `''` | `SENTINEL_CONTEXT` | Application domain separator bound into every MAC. Changing it invalidates every seal (re-seal). |
| `key_type` | `bigint`\|`uuid`\|`ulid` | `bigint` | `SENTINEL_KEY_TYPE` | Id type of sealed models in the morph columns (set before migrating). |
| `actor_key_type` | `bigint`\|`uuid`\|`ulid` | `bigint` | `SENTINEL_ACTOR_KEY_TYPE` | Id type of actors, key owners and nonce subjects. |
| `models` | list of class-strings | `[]` | — | Models `sentinel:verify` scans when given none. |
| `database.connection` | ?string | `null` | `SENTINEL_DB_CONNECTION` | Connection of `sentinel_keys`, `sentinel_idempotency_keys`, `sentinel_nonces`. |
| `keys.default_ring` | string | `default` | `SENTINEL_DEFAULT_RING` | Ring used by seals that name none. |
| `keys.revoked` | string (`ring:kid,…`) | `''` | `SENTINEL_REVOKED_KEYS` | Revoked keys — beats every driver, survives a restored key row. |
| `keys.rings.default.driver` | string | `config` | `SENTINEL_KEY_DRIVER` | `config`, `database`, `chain` or a custom driver. |
| `keys.rings.default.algorithms` | list | all six | — | The ring's algorithm allow-list. |
| `keys.rings.default.key_id` | ?string | `null` | `SENTINEL_KEY_ID` | Config driver: the current key id. |
| `keys.rings.default.algorithm` | string | `hmac-sha256` | `SENTINEL_ALGORITHM` | Config driver: the current key's algorithm. |
| `keys.rings.default.key` | ?string | `null` | `SENTINEL_KEY` | Config driver: `base64:` secret or private key. |
| `keys.rings.default.public_key` | ?string | `null` | `SENTINEL_PUBLIC_KEY` | Config driver: `base64:` public key (verify-only nodes). |
| `keys.rings.default.previous` | string | `''` | `SENTINEL_PREVIOUS_KEYS` | Config driver: verify-only keys, `kid\|algorithm\|base64:…` comma-separated. |
| `keys.rings.default.drivers` | list | `['config', 'database']` | — | Chain driver order. |
| `keys.rings.http.driver` | string | `database` | `SENTINEL_HTTP_KEY_DRIVER` | Driver of the RFC 9421 ring. |
| `keys.rings.http.algorithms` | list | the four RFC 9421 algorithms | — | The `http` ring's allow-list. |
| `keys.rings.http.key_id` / `algorithm` / `key` / `public_key` / `previous` / `drivers` | as above | as above | `SENTINEL_HTTP_KEY_ID`, `SENTINEL_HTTP_ALGORITHM`, `SENTINEL_HTTP_KEY`, `SENTINEL_HTTP_PUBLIC_KEY`, `SENTINEL_HTTP_KEYS` | When the `http` ring uses the config driver. |
| `sealing.auto` | bool | `true` | `SENTINEL_AUTO_SEAL` | Seal on Eloquent writes (turn off on verify-only nodes). |
| `sealing.on_tampered_write` | `refuse`\|`reseal`\|`skip` | `refuse` | `SENTINEL_ON_TAMPERED_WRITE` | What an Eloquent write does to a model that is not intact. |
| `sealing.allow_suspension` | bool | `true` | `SENTINEL_ALLOW_SUSPENSION` | Permit `Sentinel::withoutSealing()`. |
| `sealing.field_tags` | bool | `true` | `SENTINEL_FIELD_TAGS` | Keyed per-field tags that name changed attributes (HMAC keys). |
| `sealing.reason_max_length` | int 1–10000 | `1000` | — | Acknowledgement, unseal and baseline reasons. |
| `sealing.transaction_attempts` | int 1–10 | `3` | — | Retries of Sentinel's own transactions (never the host's `save()`). |
| `verification.check_ledger` | bool | `true` | `SENTINEL_VERIFY_LEDGER` | Compare seals with the ledger (detects replayed seals). |
| `verification.outdated_is_intact` | bool | `true` | `SENTINEL_OUTDATED_IS_INTACT` | A changed definition over intact data counts as intact. |
| `verification.log_channel` | ?string | `null` | `SENTINEL_LOG_CHANNEL` | Where findings are logged (null = default channel). |
| `verification.retrieve_reaction` | `throw`\|`event`\|`log` | `throw` | `SENTINEL_RETRIEVE_REACTION` | Default reaction of verify-on-retrieve. |
| `verification.retrieve_checks_ledger` | bool | `false` | `SENTINEL_RETRIEVE_CHECKS_LEDGER` | Ledger check on retrieve (one more query per model). |
| `acknowledgement.ability` | ?string | `null` | `SENTINEL_ACKNOWLEDGE_ABILITY` | Gate ability checked before an acknowledgement. |
| `ledger.enabled` | bool | `true` | `SENTINEL_LEDGER` | Write ledger entries (off loses replay/rollback detection). |
| `ledger.ring` | string | `default` | `SENTINEL_LEDGER_RING` | Ring whose current key signs checkpoints. |
| `ledger.connections` | list | `[null]` | — | Connections holding seals and the ledger. |
| `ledger.batch_size` | int 1–100000 | `1000` | — | Entries per checkpoint transaction. |
| `ledger.backlog_warning_seconds` | int 60–86400 | `600` | — | Age of un-checkpointed entries reported as a backlog. |
| `ledger.anchors` | string (comma list) | `''` | `SENTINEL_ANCHORS` | `cache`, `filesystem`, `log` or custom anchors. |
| `ledger.anchor_drivers.cache.store` | ?string | `null` | `SENTINEL_ANCHOR_CACHE_STORE` | Cache store of the cache anchor (not the app database). |
| `ledger.anchor_drivers.cache.key` | string | `sentinel:ledger:anchor` | — | Cache key prefix. |
| `ledger.anchor_drivers.filesystem.disk` | string | `local` | `SENTINEL_ANCHOR_DISK` | Disk of the filesystem anchor (object lock recommended). |
| `ledger.anchor_drivers.filesystem.path` | string | `sentinel/anchors` | `SENTINEL_ANCHOR_PATH` | Directory on that disk. |
| `ledger.anchor_drivers.log.channel` | ?string | `null` | `SENTINEL_ANCHOR_LOG_CHANNEL` | Log channel of the write-only log anchor. |
| `middleware.verified_status` | int 400–599 | `409` | — | Status of `sentinel.verified` on a failed check. |
| `middleware.verified_reaction` | `abort`\|`report` | `abort` | `SENTINEL_VERIFIED_REACTION` | Abort, or only report and continue. |
| `idempotency.store` | string | `database` | `SENTINEL_IDEMPOTENCY_STORE` | `database`, `cache` or a bound custom store. |
| `idempotency.cache_store` | ?string | `null` | `SENTINEL_IDEMPOTENCY_CACHE_STORE` | Lock-capable cache store for the cache store. |
| `idempotency.header` | string | `Idempotency-Key` | — | Request header. |
| `idempotency.replay_header` | string | `Idempotent-Replayed` | — | Header on replayed responses. |
| `idempotency.methods` | list | `['POST', 'PATCH']` | — | Methods the middleware applies to. |
| `idempotency.ttl` | int 60–2592000 | `86400` | `SENTINEL_IDEMPOTENCY_TTL` | Seconds a key lives after it was first seen. |
| `idempotency.lock_seconds` | int 1–3600 | `60` | — | Lease of a request in progress. |
| `idempotency.min_length` / `max_length` | int | `16` / `255` | — | Accepted key length. |
| `idempotency.accept_unquoted` | bool | `true` | `SENTINEL_IDEMPOTENCY_ACCEPT_UNQUOTED` | Accept bare (unquoted) keys. |
| `idempotency.store_client_errors` | bool | `true` | — | Store and replay 4xx responses. |
| `idempotency.store_server_errors` | bool | `false` | — | Store 5xx responses (default: release the key). |
| `idempotency.transactional` | bool | `false` | `SENTINEL_IDEMPOTENCY_TRANSACTIONAL` | Handler and record in one transaction. |
| `idempotency.encrypt` | bool | `true` | `SENTINEL_IDEMPOTENCY_ENCRYPT` | Encrypt stored responses. |
| `idempotency.max_response_bytes` | int 1024–67108864 | `1048576` | — | Larger responses are not replayable. |
| `idempotency.replayed_headers` | list | `content-type`, `content-language`, `location`, `etag`, `last-modified`, `cache-control` | — | Headers stored and replayed (`set-cookie` never). |
| `nonces.store` | string | `database` | `SENTINEL_NONCE_STORE` | `database`, `cache` or a bound custom store. |
| `nonces.cache_store` | ?string | `null` | `SENTINEL_NONCE_CACHE_STORE` | Lock-capable cache store. |
| `nonces.ttl` | int 1–2592000 | `900` | — | Seconds a nonce lives. |
| `nonces.length` | int 32–128 | `43` | — | Nonce length in base64url characters (43 ≈ 256 bits). |
| `problems.type_base` | ?string | `null` | `SENTINEL_PROBLEM_TYPE_BASE` | RFC 9457 `type` = base + `#code` (null: omitted). |
| `signatures.default_profile` | string | `default` | — | Profile of `sentinel.signed` without a parameter. |
| `signatures.profiles.<name>.ring` | string | `http` | — | Ring the profile's key ids resolve in. |
| `signatures.profiles.<name>.label` | ?string | `null` | — | Signature label to verify (null: the only one, or the one with the profile tag). |
| `signatures.profiles.<name>.tag` | ?string | `null` | — | Required `tag` parameter. |
| `signatures.profiles.<name>.components` | list | `@method`, `@authority`, `@path` | — | Components that must be covered. |
| `signatures.profiles.<name>.require_query` | bool | `true` | — | Cover `@query` when the request has a query. |
| `signatures.profiles.<name>.require_content_digest` | bool | `true` | — | Cover `content-digest` when there is a body. |
| `signatures.profiles.<name>.require_nonce` | bool | `true` | — | Require (and de-duplicate) a `nonce`. |
| `signatures.profiles.<name>.max_age` | int | `300` | — | Seconds a signature is accepted after `created`. |
| `signatures.profiles.<name>.clock_skew` | int | `30` | — | Allowed clock difference in seconds. |
| `signatures.profiles.<name>.algorithms` | list | the four RFC 9421 algorithms | — | Allowed algorithms. |
| `signatures.outbound.ring` | string | `http` | — | Ring of `Http::withSignature()` keys. |
| `signatures.outbound.label` | string | `sig1` | — | Label of outgoing signatures. |
| `signatures.outbound.components` | list | `@method`, `@authority`, `@path`, `@query`, `content-digest`, `content-type` | — | Components signed (absent ones are dropped). |
| `signatures.outbound.digest` | `sha-256`\|`sha-512` | `sha-256` | — | `Content-Digest` algorithm. |
| `signatures.outbound.expires_in` | ?int | `null` | — | Seconds until the `expires` parameter. |
| `signatures.outbound.tag` | ?string | `null` | — | `tag` parameter. |
| `signatures.outbound.include_alg` | bool | `false` | — | Send the `alg` parameter. |
| `signatures.advertise` | bool | `true` | `SENTINEL_ADVERTISE_SIGNATURE` | `Accept-Signature` on 401 responses. |

Booleans from the environment are read the way people write them: `true/false`, `on/off`,
`yes/no`, `1/0`. An invalid value throws `InvalidSentinelConfigurationException` naming the
key — security-relevant settings never fall back silently. `php artisan about` shows a
Sentinel section (rings, driver, flags, anchors, stores — never key material).

## Declaring seals

A sealable model implements `Sealable`, uses `HasSeals` and declares one or more named seals.
The first seal is the default one.

```php
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\Reaction;

final class Invoice extends Model implements Sealable
{
    use HasSeals;

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('financial')
            ->attributes('customer_id', 'currency', 'amount', 'status', 'paid', 'due_on')
            ->decimal('amount', 2)
            ->computed('lines', static fn (Invoice $invoice): array => $invoice->lines()
                ->orderBy('id')->get(['sku', 'quantity'])->toArray())
            ->algorithms(Algorithm::HmacSha256, Algorithm::Ed25519)
            ->scope(static fn (Invoice $invoice): string => (string) $invoice->tenant_id)
            ->verifyOnRetrieve(Reaction::Throw);

        $seals->seal('identity')->using(PartyIdentitySeal::class)->lenient();
    }
}
```

A reusable definition is a class implementing `Contracts\SealDefinition`:

```php
use RoundlyConsulting\Sentinel\Contracts\SealDefinition;
use RoundlyConsulting\Sentinel\Definition\SealDefinitionBuilder;

final class PartyIdentitySeal implements SealDefinition
{
    public function define(SealDefinitionBuilder $seal): void
    {
        $seal->attributes('number', 'meta')->plaintext('secret');
    }
}
```

| Builder method | Effect |
|---|---|
| `attributes(...$columns)` | Columns covered, typed from the model's casts. Never `*`; the primary key is always bound. |
| `string()`, `integer()`, `boolean()`, `decimal($column, $scale)`, `float($column, $scale)`, `datetime()`, `date()`, `json()`, `binary()`, `plaintext()` | Add columns with an explicit type. Floats must be declared with a scale; `plaintext()` seals the decrypted value of an `encrypted` cast. |
| `computed($name, $resolver, ?SealType $as)` | A value computed from the model (a static closure), e.g. related rows. |
| `ring($ring)`, `acceptRings(...$rings)`, `algorithms(...$algorithms)` | Key ring, extra rings accepted during a ring migration, algorithm allow-list. |
| `strict()` / `lenient()` | A missing seal is a finding (default) / is `Unsealed`. |
| `auto()` / `manual()` | Seal on Eloquent writes (default) / only explicitly. |
| `verifyOnRetrieve(?Reaction $reaction)` | Verify every retrieved model: `Throw`, `Event` or `Log`. |
| `fieldTags(bool)` | Store keyed per-field tags so failures name the changed attributes (HMAC keys). |
| `scope($resolver)` | A tenant (or other) scope bound into the MAC. |
| `onTamperedWrite(TamperedWritePolicy)` | Per-seal override of `sealing.on_tampered_write`. |
| `using(SealDefinition::class)` | Apply a reusable definition first; inline calls win. |

Computed values that read related rows go stale when those rows change without a save of
the owner. Re-seal the owner — `Sentinel::seal($invoice)` re-seals computed-only drift and
records it — or touch it from the child's `saved` hook (`$line->invoice->touch()`).

A definition is compiled once per process and validated as a whole: an unknown ring, an
undeclared float, a closure that is not `static`, a duplicate field — every problem is listed
in one `InvalidSealDefinitionException`. Values are canonicalized from what the database
holds (read back under a row lock), typed and engine-portable — see the technical docs for
the frozen `sentinel.seal/1` format.

## Sealing and writes

- **Automatic.** Creating a model seals it; an update re-seals the seals whose columns
  changed (seals with computed values re-seal on every update). The write and its seal are one
  transaction: if sealing fails, the write rolls back. Every Eloquent write path is covered —
  `save`, `update`, `create`, `firstOrCreate`, `updateOrCreate`, `touch`, `push`, `increment`
  and `decrement` (also `incrementEach`), `restore`, `delete`, `forceDelete` and the quiet
  variants.
- **Explicit.** `Sentinel::seal($invoice)`, `Sentinel::for($invoice)->because('…')->seal()` or
  `$invoice->seal()`. An explicit seal never launders: a tampered model must be acknowledged.
- **Tampered writes.** Before an update the row is locked and verified. A model changed
  outside the application is **refused** (`TamperedModelException`, nothing written) unless
  `sealing.on_tampered_write` (or the seal's `onTamperedWrite()`) says `reseal` (write and
  audit the previous status) or `skip` (write, leave the seal stale).
- **Deletes** are never refused. A hard delete removes the seal rows and writes a `deleted`
  tombstone to the ledger; a soft delete keeps the seal.
- **Suspension** for seeders and imports — audited by a `SealingSuspended` event, refused
  when `sealing.allow_suspension` is off:

```php
Sentinel::withoutSealing(fn () => Invoice::query()->create($row), reason: 'Legacy import');
```

- **Overriding `save()` or `delete()`** in a sealable model: route the parent call through
  `persistSealed()`, or the model refuses to boot:

```php
public function save(array $options = []): bool
{
    $this->number = trim((string) $this->number);

    return $this->persistSealed(fn (): bool => parent::save($options)) === true;
}
```

- **Verify-only nodes** (servers holding only public keys) set `SENTINEL_AUTO_SEAL=false`;
  they verify everything and seal nothing.

The trait reserves these names on your model: `seal`, `verifySeal`, `verifySealOrFail`,
`isIntact`, `acknowledgeTampering`, `persistSealed`, `sentinelSeals`, and the scopes
`whereSealed`, `whereNotSealed`, `withSeals`.

## Verifying

```php
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

$result = Sentinel::for($invoice)->verify();              // the default seal
$result = Sentinel::for($invoice, 'identity')->verify();  // a named seal
$result = Sentinel::verify($invoice, 'financial');        // the same, flat

$result->status;              // VerificationStatus::Intact, ::Tampered, …
$result->reason;              // 'mac', 'seal_deleted', 'newer_version', … (null when intact)
$result->changedAttributes;   // ['a:amount'] — names only, never values
$result->isIntact();

$invoice->isIntact();                                    // every seal
$invoice->verifySeal('identity');
Sentinel::verifyAll($invoice)->allIntact();              // VerificationReport over every seal
Sentinel::verifyMany($invoices, 'financial')->failures();
Sentinel::for($invoice)->verifyOrFail();                  // TamperedModelException when not intact
```

| Status | Meaning |
|---|---|
| `Intact` | The seal matches the stored values and the ledger. |
| `Outdated` | Intact, but sealed under an older definition (counts as intact by default; `sentinel:reseal --only-outdated`). |
| `Unsealed` | A lenient seal that was never written. |
| `Tampered` | Values changed outside the application (`mac`), or no longer canonicalize (`canonicalization`), or a ledger entry was forged (`ledger_entry`). |
| `Missing` | A strict seal is absent: `seal_deleted` (history exists), `never_sealed`, `unsealed`. |
| `Stale` | An older seal was restored: `newer_version`, `not_in_ledger`, `ledger_mismatch`. |
| `UnknownKey`, `RevokedKey`, `RetiredKey` | The sealing key is unknown/pending/damaged, revoked or retired. |
| `AlgorithmNotAllowed`, `AlgorithmMismatch` | The key's algorithm is not allowed / differs from the stored one. |
| `Malformed`, `Unverifiable` | The seal row is damaged / a sealed column is missing. |

Every failure fires `TamperDetected` and is logged (names only, never values).

## Acknowledging out-of-band changes

A model changed outside the application stays refused until someone with a reason accepts
the change. The new seal records the previous status, the changed attribute names, the actor
and the reason in the MAC'd ledger:

```php
$result = Sentinel::for($invoice)->by($admin)->because('INC-88: refund fixed by the DBA')->acknowledge();

$result->acknowledged;   // false when the model was intact (nothing written)
$result->before;         // the VerificationResult it replaced

$invoice->acknowledgeTampering('INC-88: refund fixed by the DBA', $admin);
```

A reason is always required (1–`sealing.reason_max_length` characters); an actor is required
outside the console. Set `acknowledgement.ability` to check a Gate ability (it receives the
model and the seal name), or bind your own `Contracts\AcknowledgementPolicy`.

Other per-model operations on the handle: `seal()`, `unseal($reason)` (removes the seal with
an `unsealed` tombstone), `current()` (the stored seal row, unverified), `history($limit)`
(ledger records), `definition()` and `name()`.

## Bulk operations

`Sentinel::model(Invoice::class)` works on every row of a model:

```php
$seals = Sentinel::model(Invoice::class);

$seals->scan();                                     // ScanReport: counts per status + findings
$seals->sealMissing(reason: 'Initial baseline');    // adopt rows that were never sealed
$seals->reseal();                                   // re-seal intact rows with the current key
$seals->reseal(acknowledgeReason: 'INC-90');        // …and acknowledge the others
$seals->resealWhere(fn ($query) => $query->where('status', 'draft'), reason: 'INC-91', actor: $admin);
$seals->updateAndReseal(
    fn ($query) => $query->where('status', 'draft'), ['currency' => 'EUR'], reason: 'FIN-12 currency migration', actor: $admin,
);
$seals->unsealedQuery()->count();                   // rows without a seal row
$seals->seals();                                    // ['financial', 'identity']
```

Re-sealing **never launders**: rows that are not intact are skipped and reported unless an
acknowledgement reason is given. `updateAndReseal()` verifies every selected row first and
writes nothing if one is not intact.

## Ledger, checkpoints and anchors

Every seal event appends an entry to `sentinel_ledger`, MAC'd over its audit fields. The
scheduled `sentinel:checkpoint` folds new entries into chained, keyed checkpoints and
publishes the newest checkpoint to the configured anchors:

```php
Sentinel::ledger()->checkpoint();                    // CheckpointResult or null
$report = Sentinel::ledger()->verify();             // LedgerReport
$report->clean();
$report->findings;                                  // list<LedgerFinding>
Sentinel::ledger()->history($invoice);              // list<LedgerRecord>
Sentinel::ledger()->head();                         // the newest checkpoint
Sentinel::ledger()->anchors();                      // ['cache']
```

Without an anchor, restoring the **whole** database to an older backup is undetectable. Set
`SENTINEL_ANCHORS=cache` (a Redis that is not the application database) or `filesystem` (object
storage with object lock), or `log` (write-only; compare with
`sentinel:verify --ledger --anchor='<json>'`). Custom anchors: see [Extending](#extending).
The ledger is never pruned.

## Middleware, validation rule, collection macro and scopes

| Alias | Parameters | Behaviour |
|---|---|---|
| `sentinel.verified` | none = every route model; or `param[@seal],…` | Verifies route models after route-model binding; a failure answers `middleware.verified_status` (409) with a generic message — never the status or reason. |
| `sentinel.idempotent` | `optional` (default) or `required`, optional TTL seconds | [Idempotency keys](#idempotency-keys). |
| `sentinel.signed` | optional profile name | [HTTP message signatures](#http-message-signatures). |
| `sentinel.single-use` | — | [Single-use URLs](#nonces-and-single-use-urls). |

```php
Route::get('/invoices/{invoice}', ShowInvoice::class)->middleware('sentinel.verified');
Route::put('/invoices/{invoice}/lines/{line}', UpdateLine::class)->middleware('sentinel.verified:invoice@financial');
```

Recommended order: `sentinel.signed` → `auth` → `sentinel.idempotent` → (bindings) →
`sentinel.verified`.

```php
use RoundlyConsulting\Sentinel\Rules\IntactSeal;

$request->validate(['invoice_id' => ['required', new IntactSeal(Invoice::class, seal: 'financial')]]);

$report = Invoice::query()->withSeals()->get()->verifySeals();   // reuses the eager-loaded seals
Invoice::query()->whereSealed()->count();
Invoice::query()->whereNotSealed('identity')->get();
```

## Idempotency keys

Clients send `Idempotency-Key: "<uuid>"` (draft-ietf-httpapi-idempotency-key-header-07). The
first request runs; repeats replay the stored response with `Idempotent-Replayed: true`; the
same key with another payload answers **422**, a request still in flight **409** with
`Retry-After`. 5xx responses release the key so the client may retry. Keys expire
`idempotency.ttl` seconds (24 hours by default) after they were first seen; `Set-Cookie` is
never stored; stored responses are encrypted. Keys are scoped to the user (or the verified
signature key, or the IP) and the route.

```php
Route::post('/orders', StoreOrder::class)->middleware(['auth:sanctum', 'sentinel.idempotent:required']);

Http::withIdempotencyKey()->post('https://api.example.com/orders', $payload);   // client side
```

For jobs, commands and webhooks:

```php
$result = Sentinel::idempotency()->run("charge:{$order->id}", scope: 'billing', callback: fn () => $gateway->charge($order));

$result->value;       // the callback's (JSON-encodable) result, replayed on repeats
$result->replayed;
Sentinel::idempotency()->forget("charge:{$order->id}", scope: 'billing');
```

Rejections are RFC 9457 `application/problem+json` responses with a `code` member. With
`idempotency.transactional` on, the handler and the idempotency record commit in one
transaction (exactly once for that connection's writes — at the cost of holding the
transaction for the request).

## Nonces and single-use URLs

```php
$nonce = Sentinel::nonces()->issue('password-reset', ttl: 900, subject: $user);
$nonce->value;        // 43 characters (≈ 256 bits); only its SHA-256 is stored

Sentinel::nonces()->consume('password-reset', $token, $user);        // true exactly once
Sentinel::nonces()->consumeOrFail('password-reset', $token, $user);  // 403 problem otherwise
```

A wrong purpose, another subject, an expired, used or unknown nonce are indistinguishable
(`false`). Single-use signed URLs:

```php
$url = Sentinel::nonces()->signedRoute('exports.download', ['export' => $export->id], ttl: 600);

Route::get('/exports/{export}', DownloadExport::class)->name('exports.download')->middleware('sentinel.single-use');
```

The second visit — or a tampered, expired or moved link — answers 403. `sentinel:prune`
deletes expired idempotency keys and nonces.

## HTTP message signatures

Partners sign requests with RFC 9421 HTTP Message Signatures (`hmac-sha256`, `ed25519`,
`ecdsa-p256-sha256`, `ecdsa-p384-sha384`; RFC 9530 `Content-Digest`). Their keys live in the
`http` ring — a partner's secret can never produce or verify a seal.

```php
use RoundlyConsulting\Sentinel\Enums\Algorithm;

$key = Sentinel::keys()->ring('http')->generate(Algorithm::Ed25519, keyId: 'acme-2026-10', owner: $partner);
$key->publicKey;      // base64:… — share it with the partner
```

Inbound — the default profile requires `created`, `keyid` and a `nonce`, accepts signatures
up to 300 seconds old (± 30 seconds of clock skew), and requires `content-digest` whenever
there is a body:

```php
Route::post('/partner/events', PartnerEvents::class)->middleware('sentinel.signed');

$signature = $request->attributes->get('sentinel.signature');   // VerifiedSignature: keyId, algorithm, created, …
```

A rejection answers 401 problem details with a generic `code` (the precise reason only with
`app.debug`) and an `Accept-Signature` hint; `HttpSignatureRejected` carries the reason.
Add profiles under `sentinel.signatures.profiles` and name them: `sentinel.signed:partners`.

Outbound — sign requests with a key of the outbound ring:

```php
Http::withSignature('acme-2026-10')->post('https://partner.example/events', $event);

Sentinel::signatures()->verifyResponse($response, 'partners');   // a signed response
Sentinel::signatures()->contentDigest('{"hello": "world"}');      // 'sha-256=:X48E…:'
```

## Key management

Keys live in named **rings** (`default` for seals, the ledger and checkpoints; `http` for
message signatures; add your own). A key id resolves only in its own ring, and the algorithm
always comes from the key — never from a stored row or a received parameter.

| Driver | Keys come from | Rotation |
|---|---|---|
| `config` (default ring) | `SENTINEL_KEY_ID` / `SENTINEL_KEY` (+ `SENTINEL_PREVIOUS_KEYS` for verify-only keys) | `sentinel:key:rotate` prints the new environment lines |
| `database` (`http` ring) | `sentinel_keys` rows: encrypted with `APP_KEY`, every field bound, so an edited row is rejected | `sentinel:key:rotate` stores the new key; the old one becomes verify-only |
| `chain` | the `drivers` in order (the first signing key wins) | per driver |

Material is always `base64:<standard base64>`: HMAC roots of 32–1024 random bytes, Ed25519
64-byte secret keys or 32-byte public keys, ECDSA PEM (base64-encoded). Statuses follow NIST
SP 800-57: pending → active → verify-only → retired, plus revoked. `SENTINEL_REVOKED_KEYS`
(`ring:kid,…`) revokes a key whatever its driver says — it survives a restored database row.

```php
Sentinel::keys()->ring()->current();                        // KeyInfo of the signing key
Sentinel::keys()->ring('http')->all();
Sentinel::keys()->ring('http')->rotate();
Sentinel::keys()->ring('http')->revoke('acme-2026-10', reason: 'Partner offboarded');
Sentinel::keys()->ring('http')->retire('acme-2025-10');
Sentinel::keys()->all();                                    // every ring
```

Prefer the `config` driver for the default ring: database-driver keys are only as safe as
`APP_KEY`. A verify-only node (asymmetric keys) configures `SENTINEL_KEY_ID`,
`SENTINEL_ALGORITHM` and `SENTINEL_PUBLIC_KEY` without `SENTINEL_KEY`, and
`SENTINEL_AUTO_SEAL=false`. Material never appears in exceptions, logs, events, `about`,
`var_dump()` or serialized data.

## Commands and scheduling

| Command | Purpose |
|---|---|
| `sentinel:verify {model?*} {--seal=} {--chunk=500} {--limit=} {--ledger} {--anchor=} {--check-schema} {--json} {--fail-on=*} {--max-findings=1000}` | Scan sealed rows (and the ledger); exit 1 on findings — for cron and CI. |
| `sentinel:checkpoint {--connection=*} {--batch=}` | Fold pending ledger entries into checkpoints and publish them to the anchors. |
| `sentinel:reseal {model} {--seal=} {--from-key=} {--only-outdated} {--upgrade-format} {--chunk=500} {--dry-run} {--acknowledge=}` | Re-seal after a rotation or definition change; never launders without `--acknowledge`. |
| `sentinel:seal-missing {model} {--seal=} {--reason=} {--chunk=500}` | Baseline rows that were never sealed. |
| `sentinel:inspect {model} {id} {--seal=} {--show-values} {--check-schema}` | One row: seal row, verdict, manifest, history, changed fields (values only with `--show-values`). |
| `sentinel:prune {--idempotency} {--nonces} {--dry-run}` | Delete expired idempotency keys and nonces. |
| `sentinel:key:generate {--ring=} {--algorithm=hmac-sha256} {--kid=} {--database} {--activate-at=} {--owner-type=} {--owner-id=} {--label=}` | Generate a key (environment lines, or a database row). |
| `sentinel:key:rotate {--ring=} {--algorithm=} {--activate-at=}` | Rotate a ring's signing key. |
| `sentinel:key:revoke {kid} {--ring=} {--reason=}` | Revoke a key. |
| `sentinel:key:retire {kid} {--ring=} {--force}` | Retire a key (refused while seals still use it). |
| `sentinel:key:list {--ring=}` | The key inventory — never material. |

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('sentinel:checkpoint')->everyMinute();
Schedule::command('sentinel:verify --ledger')->hourly();
Schedule::command('sentinel:prune')->daily();
```

## Events

Payloads are scalars only (types, ids, seal names, statuses, attribute names, key ids) — never
values, key material or request bodies — so they are safe for queued listeners.

| Event | When | Payload |
|---|---|---|
| `ModelSealed` | after commit | sealable type/id, seal, version, key id, `SealEvent`, actor |
| `TamperDetected` | sync | sealable type/id, seal, `VerificationStatus`, reason, changed attributes, context, key id |
| `TamperAcknowledged` | after commit | sealable type/id, seal, version, previous status, changed attributes, reason, actor |
| `SealRemoved` | after commit | sealable type/id, seal, `deleted`/`unsealed`, previous status |
| `SealingSuspended` | sync | reason, actor |
| `KeyGenerated`, `KeyRotated`, `KeyRevoked`, `KeyRetired` | after commit | ring, key id, algorithm (+ previous key id / reason and actor) |
| `KeyIntegrityViolated` | sync | ring, key id, driver |
| `LedgerCheckpointed` | after commit | connection, seq, entries, root |
| `LedgerIntegrityViolated` | sync | connection, `LedgerFinding`s |
| `AnchorPublishFailed` | sync | anchor, connection, seq, error |
| `IdempotentRequestReplayed`, `IdempotencyRejected` | sync | method, route, status (+ `IdempotencyRejection`) |
| `HttpSignatureRejected` | sync | `SignatureRejection`, key id, method, path |

All live in `RoundlyConsulting\Sentinel\Events`.

## Extending

```php
use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;

// A key-store driver (e.g. a KMS): name it in keys.rings.<ring>.driver.
Sentinel::extend('vault', fn (Container $app, string $ring, array $config): KeyStore => new VaultKeyStore($ring, $config));

// An anchor: name it in SENTINEL_ANCHORS.
Sentinel::extendAnchor('s3-lock', fn (Container $app, array $config): Anchor => new ObjectLockAnchor($config));
```

Bind your own implementation of `Contracts\IdempotencyStore`, `Contracts\NonceStore`,
`Contracts\IdempotencyScopeResolver` or `Contracts\AcknowledgementPolicy` (for example a
two-person approval) in a service provider.

## Without the facade

The facade, the injected manager and the actions run the same code:

```php
use RoundlyConsulting\Sentinel\Actions\Seals\AcknowledgeTamperingAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\SentinelManager;

final class FixInvoice
{
    public function __construct(private SentinelManager $sentinel) {}

    public function __invoke(Invoice $invoice, User $admin): void
    {
        $this->sentinel->for($invoice)->by($admin)->because('Ticket #412: corrected VAT via SQL')->acknowledge();
    }
}

app(AcknowledgeTamperingAction::class)->execute(new AcknowledgeRequest(
    model: $invoice, seal: 'financial', reason: 'Ticket #412: corrected VAT via SQL', actor: $admin,
));
```

Every facade method that seals, verifies or changes state (`seal`, `verify`, `acknowledge`,
`scan`, `reseal`, `checkpoint`, `generateKey`, `runIdempotent`, `issueNonce`, `signRequest`, …)
resolves one action from the container, so binding your own action class overrides it
everywhere — the handles, sub-accessors and model trait go through the same manager.

## Testing your application

`Sentinel::fake()` swaps the manager (in the facade and the container) for a recording fake
that needs no keys and writes no seals. It keeps production semantics where tests rely on
them: definitions are compiled for real, the tampered-write policy applies to faked statuses,
reasons, actors and the acknowledgement policy are enforced, and idempotency and nonces run
the real state machine in memory.

```php
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

$fake = Sentinel::fake();

$fake->fakeStatus($invoice, VerificationStatus::Tampered, 'financial', changed: ['a:amount']);
$this->get("/invoices/{$invoice->id}")->assertStatus(409);

Sentinel::assertVerified($invoice);
Sentinel::assertNothingAcknowledged();
```

Controls: `fakeStatus()` (sticky until the fake re-seals or acknowledges that seal, as
production would), `fakeStatusOnce()`, `fakeVerifiedSignature()`, `rejectSignatures()`,
`recorded()`. Assertions: `assertSealed`, `assertNotSealed`, `assertNothingSealed`,
`assertVerified`, `assertNothingVerified`, `assertAcknowledged`, `assertNothingAcknowledged`,
`assertUnsealed`, `assertSealingSuspended`, `assertKeyGenerated`, `assertKeyRotated`,
`assertKeyRevoked`, `assertNoKeyChanges`, `assertCheckpointed`, `assertResealed`,
`assertIdempotentRun`, `assertNonceIssued`, `assertNonceConsumed`, `assertRequestSigned`.

## Naming

Import `RoundlyConsulting\Sentinel\Facades\Sentinel` and `RoundlyConsulting\Sentinel\SentinelManager`
explicitly — the package registers **no global alias**. `cartalyst/sentinel` registers a
global `Sentinel` alias that ours would replace, and `laravel/sentinel` (installed with Horizon,
Pulse and Telescope) ships its own `Laravel\Sentinel\Sentinel` and `SentinelManager`, which an
IDE may auto-import. `php artisan about` shows the manager's full class name.

## Testing

```bash
composer test            # the suite
composer test-coverage   # ≥ 95 % overall, 100 % on the security-critical namespaces
composer perf            # a non-gating performance smoke
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Contributing

See the organisation's [contributing guide](https://github.com/roundly-consulting/.github/blob/main/CONTRIBUTING.md).

<!-- roundly-support:start -->
## Support our work

This package is free and open source, built and maintained by
[Roundly Consulting](https://roundly-consulting.com/open-source?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel).
If it saves you time, please consider supporting our open-source work — a one-time donation, a
monthly pledge on Patreon or a crypto donation helps fund maintenance, new features and new
packages.

<a href="https://donate.stripe.com/dRmeVe8FX5PF1Qd9pXcEw00"><img src="https://img.shields.io/badge/Donate-Support%20Roundly%20open%20source-F24E29?style=for-the-badge&logo=stripe&logoColor=white" alt="Donate to Roundly open source"></a>
<a href="https://www.patreon.com/cw/roundly"><img src="https://img.shields.io/badge/Patreon-Become%20a%20patron-F96854?style=for-the-badge&logo=patreon&logoColor=white" alt="Become a patron on Patreon"></a>
<a href="https://roundly-consulting.com/support-us?utm_source=github&utm_medium=readme&utm_campaign=open-source&utm_content=sentinel-for-laravel#crypto"><img src="https://img.shields.io/badge/Crypto-BTC%20%C2%B7%20ETH%20%C2%B7%20BNB%20%C2%B7%20SOL-F7931A?style=for-the-badge&logo=bitcoin&logoColor=white" alt="Donate crypto: BTC, ETH, BNB or SOL"></a>
<!-- roundly-support:end -->

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
