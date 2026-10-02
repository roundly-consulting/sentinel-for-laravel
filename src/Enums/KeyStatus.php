<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * A key's effective lifecycle status (NIST SP 800-57 usage periods). The stored manual
 * state of a database key is one of `active`, `verify_only`, `retired`, `revoked`; the
 * effective status also folds in the dates and the configured revocation list.
 */
enum KeyStatus: string
{
    use Helpers;

    case Pending = 'pending';
    case Active = 'active';
    case VerifyOnly = 'verify_only';
    case Retired = 'retired';
    case Revoked = 'revoked';

    public function canSign(): bool
    {
        return $this === self::Active;
    }

    public function canVerify(): bool
    {
        return $this === self::Active || $this === self::VerifyOnly;
    }
}
