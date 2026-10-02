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
    | The id type of actors, key owners and nonce subjects in Sentinel's tables:
    | bigint, uuid or ulid. Set it before running the published migrations.
    |
    */

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

];
