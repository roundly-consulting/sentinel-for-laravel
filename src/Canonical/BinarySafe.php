<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use RoundlyConsulting\Crypto\Codec\Base64Url;

/**
 * An injective JSON form for raw bytes that may not be UTF-8 (a raw request path, a stored
 * column an attacker filled with binary): valid UTF-8 stays a JSON string, anything else
 * becomes `["b", base64url]`. A string and an array never collide, so two different byte
 * strings never canonicalize the same.
 *
 * @internal
 */
final class BinarySafe
{
    /**
     * @return string|list<string>|null
     */
    public static function value(?string $bytes): string|array|null
    {
        if ($bytes === null) {
            return null;
        }

        return mb_check_encoding($bytes, 'UTF-8') ? $bytes : ['b', Base64Url::encode($bytes)];
    }
}
