<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Enums\Helpers;

/**
 * The RFC 9530 `Content-Digest` algorithms Sentinel produces and accepts (the "active"
 * registry entries).
 */
enum DigestAlgorithm: string
{
    use Helpers;

    case Sha256 = 'sha-256';
    case Sha512 = 'sha-512';

    public function hashAlgorithm(): HashAlgorithm
    {
        return match ($this) {
            self::Sha256 => HashAlgorithm::Sha256,
            self::Sha512 => HashAlgorithm::Sha512,
        };
    }
}
