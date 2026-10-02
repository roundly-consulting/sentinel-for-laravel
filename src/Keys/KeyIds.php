<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Generated key ids: `<ring>-<Ymd>-<6 lowercase alnum>` (CSPRNG), e.g. `default-20261002-k3f9qa`.
 *
 * @internal
 */
final class KeyIds
{
    private const string ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

    public static function generate(string $ring): string
    {
        $suffix = Clock::now()->format('Ymd').'-'.(new Csprng)->fromAlphabet(self::ALPHABET, 6);
        $keyId = "{$ring}-{$suffix}";

        return strlen($keyId) <= 64 ? $keyId : "k-{$suffix}";
    }
}
