<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The outcome of verifying one seal of one model. Every value except `intact`, `unsealed`
 * and (by default) `outdated` is a finding.
 */
enum VerificationStatus: string
{
    use Helpers;

    case Intact = 'intact';
    case Outdated = 'outdated';
    case Unsealed = 'unsealed';
    case Tampered = 'tampered';
    case Missing = 'missing';
    case Stale = 'stale';
    case UnknownKey = 'unknown_key';
    case RevokedKey = 'revoked_key';
    case RetiredKey = 'retired_key';
    case AlgorithmNotAllowed = 'algorithm_not_allowed';
    case AlgorithmMismatch = 'algorithm_mismatch';
    case Malformed = 'malformed';
    case Unverifiable = 'unverifiable';

    public function isIntact(bool $outdatedIsIntact = true): bool
    {
        return match ($this) {
            self::Intact, self::Unsealed => true,
            self::Outdated => $outdatedIsIntact,
            default => false,
        };
    }

    public function isFailure(bool $outdatedIsIntact = true): bool
    {
        return ! $this->isIntact($outdatedIsIntact);
    }
}
