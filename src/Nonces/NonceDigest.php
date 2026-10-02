<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Nonces;

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use SensitiveParameter;

/**
 * Nonces are stored as base64url SHA-256 digests only — a database read cannot replay them.
 *
 * @internal
 */
final class NonceDigest
{
    public static function of(#[SensitiveParameter] string $nonce): string
    {
        return Base64Url::encode((new Digest)->raw($nonce));
    }

    /**
     * The purpose of a route's single-use URLs: `url:<route name>`, or a digest of a name
     * outside the purpose alphabet.
     */
    public static function routePurpose(string $route): string
    {
        $purpose = 'url:'.$route;

        return Identifiers::isPurpose($purpose) ? $purpose : 'url:h.'.(new Digest)->hex($route);
    }
}
