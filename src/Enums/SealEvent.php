<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Why a ledger entry was written. Tombstones (`deleted`, `unsealed`) carry no seal MAC.
 */
enum SealEvent: string
{
    use Helpers;

    case Sealed = 'sealed';
    case Resealed = 'resealed';
    case Acknowledged = 'acknowledged';
    case Baseline = 'baseline';
    case Rotated = 'rotated';
    case Deleted = 'deleted';
    case Unsealed = 'unsealed';

    public function isTombstone(): bool
    {
        return $this === self::Deleted || $this === self::Unsealed;
    }
}
