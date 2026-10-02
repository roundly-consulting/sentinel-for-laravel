<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\StringEncrypter;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Stored responses at rest: encrypted with the application key when `idempotency.encrypt` is
 * on (the default), readable either way (rotated keys decrypt through `app.previous_keys`).
 * Anything that no longer opens is unusable — the key then answers 409, never a guess.
 *
 * @internal
 */
final readonly class ResponseVault
{
    public function __construct(private StringEncrypter $encrypter) {}

    public function seal(ResponseSnapshot $snapshot): string
    {
        $json = $snapshot->toJson();

        return Settings::idempotencyEncrypt() ? $this->encrypter->encryptString($json) : $json;
    }

    public function open(string $payload): ?ResponseSnapshot
    {
        try {
            return ResponseSnapshot::fromJson(str_starts_with($payload, '{') ? $payload : $this->encrypter->decryptString($payload));
        } catch (DecryptException|CorruptRecordException) {
            return null;
        }
    }
}
