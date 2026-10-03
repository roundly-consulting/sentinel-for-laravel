<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Illuminate\Contracts\Encryption\DecryptException;
use RoundlyConsulting\Sentinel\Canonical\Jcs;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Keys\StorageCipher;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Stored responses at rest: encrypted when `idempotency.encrypt` is on (the default) by
 * {@see StorageCipher} — a key derived from APP_KEY for stored responses only (rotated keys
 * decrypt through `app.previous_keys`), bound to the store, the key's digest and its scope as
 * associated data. So a response copied to another key never opens (no one replays another
 * user's stored token), nothing the application encrypter made opens, and — while encryption
 * is on — a plaintext response planted in the store is refused instead of replayed.
 *
 * With encryption off responses are stored as plaintext JSON, which anyone who can write the
 * store can rewrite. Anything that does not open is unusable — the key then answers 409,
 * never a guess.
 *
 * @internal
 */
final readonly class ResponseVault
{
    public function __construct(private StorageCipher $cipher) {}

    public function seal(ResponseSnapshot $snapshot, IdempotentRequest $request, string $store): string
    {
        $json = $snapshot->toJson();

        return Settings::idempotencyEncrypt()
            ? $this->cipher->encrypt(StorageCipher::IDEMPOTENT_RESPONSE, $json, self::identity($request, $store))
            : $json;
    }

    public function open(string $payload, IdempotentRequest $request, string $store): ?ResponseSnapshot
    {
        try {
            if (str_starts_with($payload, '{')) {
                return Settings::idempotencyEncrypt() ? null : ResponseSnapshot::fromJson($payload);
            }

            return ResponseSnapshot::fromJson($this->cipher->decrypt(StorageCipher::IDEMPOTENT_RESPONSE, $payload, self::identity($request, $store)));
        } catch (DecryptException|CorruptRecordException) {
            return null;
        }
    }

    private static function identity(IdempotentRequest $request, string $store): string
    {
        return Jcs::encode(['key' => $request->keyDigest, 'scope' => $request->scope, 'store' => $store, 'v' => 'sentinel.idempotent-response/1']);
    }
}
