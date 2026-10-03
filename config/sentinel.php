<?php

declare(strict_types=1);

$algorithms = ['hmac-sha256', 'hmac-sha384', 'hmac-sha512', 'ed25519', 'ecdsa-p256-sha256', 'ecdsa-p384-sha384'];

return [

    /*
    |--------------------------------------------------------------------------
    | Context
    |--------------------------------------------------------------------------
    |
    | An application-level domain separator bound into every seal, ledger entry,
    | checkpoint and field tag. Two applications that share signing keys but use
    | different contexts can never forge each other's seals. Set it once:
    | changing it invalidates every existing seal (re-adopt them with
    | `sentinel:reseal --acknowledge="context change"`) and, permanently, every
    | ledger entry and checkpoint written before — a new context is a new ledger.
    |
    */

    'context' => env('SENTINEL_CONTEXT', ''),

    /*
    |--------------------------------------------------------------------------
    | Morph key types
    |--------------------------------------------------------------------------
    |
    | The id type of sealed models (`key_type`) and of actors, key owners and
    | nonce subjects (`actor_key_type`) in Sentinel's tables: bigint, uuid or
    | ulid. A fleet mixing integer and UUID keys picks uuid on MySQL and SQLite;
    | on PostgreSQL (a native uuid column) publish the migrations and make the
    | ids string(36) instead. Set both before running the published migrations.
    |
    */

    'key_type' => env('SENTINEL_KEY_TYPE', 'bigint'),

    'actor_key_type' => env('SENTINEL_ACTOR_KEY_TYPE', 'bigint'),

    /*
    |--------------------------------------------------------------------------
    | Models
    |--------------------------------------------------------------------------
    |
    | The sealable models `php artisan sentinel:verify` scans when it is given
    | none (e.g. App\Models\Invoice::class).
    |
    */

    'models' => [],

    /*
    |--------------------------------------------------------------------------
    | Database
    |--------------------------------------------------------------------------
    |
    | The connection of `sentinel_keys` (and the idempotency/nonce tables).
    | Null uses the default connection.
    |
    */

    'database' => [
        'connection' => env('SENTINEL_DB_CONNECTION'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Keys
    |--------------------------------------------------------------------------
    |
    | Keys live in named rings; a key id resolves only inside its own ring, so
    | HTTP partner keys can never produce or verify seals. Drivers: `config`
    | (env, the default — keys never touch the database), `database` (encrypted,
    | integrity-bound envelopes), `chain` (the `drivers` in order) or one
    | registered with Sentinel::extend().
    |
    | Material is always `base64:<standard base64>`. `previous` lists verify-only
    | keys as `kid|algorithm|base64:material` separated by commas. `revoked` is
    | `ring:kid,…` and beats every driver (a restored database row stays
    | revoked). Generate keys with `php artisan sentinel:key:generate`.
    |
    */

    'keys' => [
        'default_ring' => env('SENTINEL_DEFAULT_RING', 'default'),
        'revoked' => env('SENTINEL_REVOKED_KEYS', ''),

        'rings' => [
            'default' => [
                'driver' => env('SENTINEL_KEY_DRIVER', 'config'),
                'algorithms' => $algorithms,
                'key_id' => env('SENTINEL_KEY_ID'),
                'algorithm' => env('SENTINEL_ALGORITHM', 'hmac-sha256'),
                'key' => env('SENTINEL_KEY'),
                'public_key' => env('SENTINEL_PUBLIC_KEY'),
                'previous' => env('SENTINEL_PREVIOUS_KEYS', ''),
                'drivers' => ['config', 'database'],
            ],

            // RFC 9421 HTTP message-signature keys (partners and outbound signing).
            'http' => [
                'driver' => env('SENTINEL_HTTP_KEY_DRIVER', 'database'),
                'algorithms' => ['hmac-sha256', 'ed25519', 'ecdsa-p256-sha256', 'ecdsa-p384-sha384'],
                'key_id' => env('SENTINEL_HTTP_KEY_ID'),
                'algorithm' => env('SENTINEL_HTTP_ALGORITHM', 'hmac-sha256'),
                'key' => env('SENTINEL_HTTP_KEY'),
                'public_key' => env('SENTINEL_HTTP_PUBLIC_KEY'),
                'previous' => env('SENTINEL_HTTP_KEYS', ''),
                'drivers' => ['config', 'database'],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Sealing
    |--------------------------------------------------------------------------
    |
    | auto               — seal automatically on Eloquent writes (turn off on
    |                      verify-only nodes that hold only public keys)
    | on_tampered_write  — an Eloquent write on a model that is not intact:
    |                      refuse (nothing written), reseal (write and audit the
    |                      previous status) or skip (write, leave the seal)
    | allow_suspension   — permit Sentinel::withoutSealing() (seeders, imports)
    | field_tags         — keyed per-field tags that tell which attributes
    |                      changed (HMAC keys only; never stores values)
    | reason_max_length  — acknowledgement / unseal / baseline reasons
    | transaction_attempts — retries of Sentinel's own transactions (never the
    |                      host's save())
    |
    */

    'sealing' => [
        'auto' => env('SENTINEL_AUTO_SEAL', true),
        'on_tampered_write' => env('SENTINEL_ON_TAMPERED_WRITE', 'refuse'),
        'allow_suspension' => env('SENTINEL_ALLOW_SUSPENSION', true),
        'field_tags' => env('SENTINEL_FIELD_TAGS', true),
        'reason_max_length' => 1000,
        'transaction_attempts' => 3,
    ],

    /*
    |--------------------------------------------------------------------------
    | Verification
    |--------------------------------------------------------------------------
    |
    | check_ledger — also compare the seal with the ledger (detects replayed or
    |                rolled-back seals; one indexed query)
    | outdated_is_intact — a seal whose definition changed but whose data is
    |                intact counts as intact (re-seal with sentinel:reseal)
    | log_channel  — where findings are logged (null = the default channel)
    | retrieve_reaction — what seals declared verifyOnRetrieve() do with a
    |                model that is not intact: throw (refuse to load it) or
    |                report; both fire TamperDetected and log the finding
    | retrieve_checks_ledger — also run the ledger check on retrieve (one more
    |                query per retrieved model)
    |
    */

    'verification' => [
        'check_ledger' => env('SENTINEL_VERIFY_LEDGER', true),
        'outdated_is_intact' => env('SENTINEL_OUTDATED_IS_INTACT', true),
        'log_channel' => env('SENTINEL_LOG_CHANNEL'),
        'retrieve_reaction' => env('SENTINEL_RETRIEVE_REACTION', 'throw'),
        'retrieve_checks_ledger' => env('SENTINEL_RETRIEVE_CHECKS_LEDGER', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Acknowledgement
    |--------------------------------------------------------------------------
    |
    | The Gate ability checked (with the model and seal name) before an
    | out-of-band change may be acknowledged. Null allows any actor; a reason is
    | always required and recorded.
    |
    */

    'acknowledgement' => [
        'ability' => env('SENTINEL_ACKNOWLEDGE_ABILITY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Ledger
    |--------------------------------------------------------------------------
    |
    | The append-only, MAC'd history of every seal event. Turning it off loses
    | replay/rollback detection (Stale) — keep it on.
    |
    */

    'ledger' => [
        'enabled' => env('SENTINEL_LEDGER', true),

        // The ring whose current key signs checkpoints.
        'ring' => env('SENTINEL_LEDGER_RING', 'default'),

        // Connections holding seals and the ledger (null = the default one). Hosts
        // with sealables on several connections run migrations 0002-0004 on each.
        'connections' => [null],

        // Ledger entries folded into one checkpoint transaction.
        'batch_size' => 1000,

        // Entries older than this and not yet checkpointed are reported as a
        // backlog: the scheduled `sentinel:checkpoint` is not running.
        'backlog_warning_seconds' => 600,

        /*
        | External anchors receive every new checkpoint, so a rollback of the
        | WHOLE database (ledger and checkpoints included) stays detectable.
        | Comma-separated: cache, filesystem, log, or one registered with
        | Sentinel::extendAnchor(). None by default — without one, a restore of
        | the entire database to an older snapshot is undetectable.
        */
        'anchors' => env('SENTINEL_ANCHORS', ''),

        'anchor_drivers' => [
            // Should NOT be the application database (a Redis elsewhere).
            'cache' => [
                'store' => env('SENTINEL_ANCHOR_CACHE_STORE'),
                'key' => 'sentinel:ledger:anchor',
            ],

            // Object storage with object lock / versioning is ideal.
            'filesystem' => [
                'disk' => env('SENTINEL_ANCHOR_DISK', 'local'),
                'path' => env('SENTINEL_ANCHOR_PATH', 'sentinel/anchors'),
            ],

            // Write-only: compare with `sentinel:verify --ledger --anchor=<json>`.
            'log' => [
                'channel' => env('SENTINEL_ANCHOR_LOG_CHANNEL'),
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Middleware
    |--------------------------------------------------------------------------
    |
    | `sentinel.verified` verifies the route's sealed models. On a model that is
    | not intact it aborts with `verified_status` and a generic message (never
    | the status or reason), or — with `verified_reaction` = report — only
    | reports the finding and lets the request continue.
    |
    */

    'middleware' => [
        'verified_status' => 409,
        'verified_reaction' => env('SENTINEL_VERIFIED_REACTION', 'abort'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Idempotency (the `sentinel.idempotent` middleware and Sentinel::idempotency())
    |--------------------------------------------------------------------------
    |
    | Follows draft-ietf-httpapi-idempotency-key-header-07: the key is an RFC
    | 9651 string (`Idempotency-Key: "8e03978e-…"`); a key reused with another
    | payload answers 422, one still in flight 409 (with Retry-After), and a
    | completed request replays its stored response with `Idempotent-Replayed`.
    | Keys expire `ttl` seconds after they were first seen. 5xx responses are
    | released (the client may retry); `Set-Cookie` is never stored or replayed.
    |
    | transactional — run the handler and the idempotency record in one database
    |                 transaction on `database.connection` (exactly-once for that
    |                 connection's writes; holds the transaction for the request)
    |
    */

    'idempotency' => [
        'store' => env('SENTINEL_IDEMPOTENCY_STORE', 'database'),
        'cache_store' => env('SENTINEL_IDEMPOTENCY_CACHE_STORE'),
        'header' => 'Idempotency-Key',
        'replay_header' => 'Idempotent-Replayed',
        'methods' => ['POST', 'PATCH'],
        'ttl' => env('SENTINEL_IDEMPOTENCY_TTL', 86400),
        'lock_seconds' => 60,
        'min_length' => 16,
        'max_length' => 255,
        'accept_unquoted' => env('SENTINEL_IDEMPOTENCY_ACCEPT_UNQUOTED', true),
        'store_client_errors' => true,
        'store_server_errors' => false,
        'transactional' => env('SENTINEL_IDEMPOTENCY_TRANSACTIONAL', false),
        'encrypt' => env('SENTINEL_IDEMPOTENCY_ENCRYPT', true),
        'max_response_bytes' => 1048576,
        'replayed_headers' => ['content-type', 'content-language', 'location', 'etag', 'last-modified', 'cache-control'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Nonces and single-use URLs
    |--------------------------------------------------------------------------
    |
    | Only the SHA-256 of a nonce is stored; consuming one is a single atomic
    | statement. `length` is in base64url characters (43 ≈ 256 bits). A cache
    | store must support atomic locks.
    |
    */

    'nonces' => [
        'store' => env('SENTINEL_NONCE_STORE', 'database'),
        'cache_store' => env('SENTINEL_NONCE_CACHE_STORE'),
        'ttl' => 900,
        'length' => 43,
    ],

    /*
    |--------------------------------------------------------------------------
    | Problem details (RFC 9457)
    |--------------------------------------------------------------------------
    |
    | Rejections answer `application/problem+json` with a `code` member. With a
    | base URL, `type` becomes `<base>#<code>`; without one it is omitted
    | (`about:blank`).
    |
    */

    'problems' => [
        'type_base' => env('SENTINEL_PROBLEM_TYPE_BASE'),
    ],

    /*
    |--------------------------------------------------------------------------
    | HTTP message signatures (RFC 9421)
    |--------------------------------------------------------------------------
    |
    | Inbound profiles for the `sentinel.signed[:profile]` middleware. A key id
    | resolves only inside the profile's ring (partner keys never touch seals).
    | `created` must lie within `max_age` (plus `clock_skew`), the nonce is
    | remembered for that window, `content-digest` must be covered whenever
    | there is a body, `@query` whenever there is a query. Supported: the
    | derived components @method @target-uri @authority @scheme @path @query
    | @status and header fields — no component parameters.
    |
    | `outbound` configures Http::withSignature() (keys of the outbound ring).
    | `advertise` adds Accept-Signature to 401 responses.
    |
    */

    'signatures' => [
        'default_profile' => 'default',

        'profiles' => [
            'default' => [
                'ring' => 'http',
                'label' => null,
                'tag' => null,
                'components' => ['@method', '@authority', '@path'],
                'require_query' => true,
                'require_content_digest' => true,
                'require_nonce' => true,
                'max_age' => 300,
                'clock_skew' => 30,
                'algorithms' => ['hmac-sha256', 'ed25519', 'ecdsa-p256-sha256', 'ecdsa-p384-sha384'],
                // A key this application can sign with (generated here, or imported with
                // signing: true) is refused inbound: a request it signed itself — a webhook
                // aimed back at its own API — must never pass as a partner's. True only for a
                // partner that genuinely shares one secret both ways.
                'accept_signing_keys' => false,
            ],
        ],

        'outbound' => [
            'ring' => 'http',
            'label' => 'sig1',
            'components' => ['@method', '@authority', '@path', '@query', 'content-digest', 'content-type'],
            'digest' => 'sha-256',
            'expires_in' => null,
            'tag' => null,
            'include_alg' => false,
        ],

        'advertise' => env('SENTINEL_ADVERTISE_SIGNATURE', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Scheduling
    |--------------------------------------------------------------------------
    |
    | Sentinel registers its upkeep on the Laravel scheduler (run
    | `php artisan schedule:run` every minute, as for any scheduled task), each
    | task without overlapping and on one server:
    |
    | checkpoint — `sentinel:checkpoint` (only while the ledger is on); how
    |              often decides the window in which a rollback goes unseen
    | verify     — `sentinel:verify --allow-empty` (+ `--ledger`): a full scan;
    |              daily keeps the load low, hourly suits small tables
    | prune      — `sentinel:prune` (expired idempotency keys and nonces)
    |
    | Frequencies: everyMinute, everyTwoMinutes, everyFiveMinutes,
    | everyTenMinutes, everyFifteenMinutes, everyThirtyMinutes, hourly,
    | everyTwoHours, everyThreeHours, everyFourHours, everySixHours, daily,
    | weekly — or off (a blank value is not set, so the default applies). Set
    | `enabled` to false to schedule the commands yourself.
    |
    */

    'schedule' => [
        'enabled' => env('SENTINEL_SCHEDULE', true),
        'checkpoint' => env('SENTINEL_SCHEDULE_CHECKPOINT', 'everyMinute'),
        'verify' => env('SENTINEL_SCHEDULE_VERIFY', 'daily'),
        'prune' => env('SENTINEL_SCHEDULE_PRUNE', 'daily'),
    ],

];
