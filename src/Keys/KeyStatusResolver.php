<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;

/**
 * The effective status of a key (plan §4.4.7), in precedence order: revoked (the configured
 * revocation list always wins) → retired → pending → verify-only → active.
 *
 * @internal
 */
final class KeyStatusResolver
{
    /**
     * @param  list<string>  $revoked  `ring:kid` entries of `sentinel.keys.revoked`
     */
    public static function resolve(
        string $ring,
        string $keyId,
        array $revoked,
        CarbonImmutable $now,
        ?KeyStatus $manual = null,
        ?CarbonImmutable $activatesAt = null,
        ?CarbonImmutable $signsUntil = null,
        ?CarbonImmutable $verifiesUntil = null,
        ?CarbonImmutable $revokedAt = null,
        bool $verifyOnly = false,
    ): KeyStatus {
        return match (true) {
            in_array("{$ring}:{$keyId}", $revoked, true), $revokedAt !== null, $manual === KeyStatus::Revoked => KeyStatus::Revoked,
            $manual === KeyStatus::Retired, $verifiesUntil !== null && $verifiesUntil->lessThanOrEqualTo($now) => KeyStatus::Retired,
            $activatesAt !== null && $activatesAt->greaterThan($now) => KeyStatus::Pending,
            $verifyOnly, $manual === KeyStatus::VerifyOnly, $signsUntil !== null && $signsUntil->lessThanOrEqualTo($now) => KeyStatus::VerifyOnly,
            default => KeyStatus::Active,
        };
    }
}
