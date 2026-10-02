<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use SensitiveParameter;

/**
 * The `base64:<standard base64>` encoding every key material uses in config, env and
 * database envelopes (mirrors `APP_KEY`). The prefix is mandatory: a bare string is refused,
 * which keeps passphrases out of key slots.
 *
 * @internal
 */
final class MaterialCodec
{
    public const string PREFIX = 'base64:';

    public static function decode(#[SensitiveParameter] string $encoded): string
    {
        if (! str_starts_with($encoded, self::PREFIX)) {
            throw InvalidKeyMaterialException::encodingRequired();
        }

        try {
            return Base64::decode(substr($encoded, strlen(self::PREFIX)));
        } catch (InvalidEncodingException) {
            throw InvalidKeyMaterialException::malformedEncoding();
        }
    }

    public static function encode(#[SensitiveParameter] string $bytes): string
    {
        return self::PREFIX.Base64::encode($bytes);
    }
}
