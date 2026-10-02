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
    | different contexts can never forge each other's seals. Changing it
    | invalidates every existing seal — re-seal with `sentinel:reseal`.
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
    | ulid. A fleet mixing key types picks the widest. Set both before running
    | the published migrations.
    |
    */

    'key_type' => env('SENTINEL_KEY_TYPE', 'bigint'),

    'actor_key_type' => env('SENTINEL_ACTOR_KEY_TYPE', 'bigint'),

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
    |
    */

    'verification' => [
        'check_ledger' => env('SENTINEL_VERIFY_LEDGER', true),
        'outdated_is_intact' => env('SENTINEL_OUTDATED_IS_INTACT', true),
        'log_channel' => env('SENTINEL_LOG_CHANNEL'),
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
    ],

];
