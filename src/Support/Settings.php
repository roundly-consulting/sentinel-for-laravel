<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;

/**
 * Validated readers for `config/sentinel.php`. Every value is checked at first use and an
 * invalid one throws {@see InvalidSentinelConfigurationException} — never a silent fallback
 * on a security-relevant key. Booleans and integers go through the toolkit's `Config`
 * helpers, so `SENTINEL_X=off` means off.
 */
final class Settings
{
    /**
     * The application context bound into every MAC (`sentinel.context`). Changing it
     * invalidates every seal, by design: two apps sharing keys cannot forge each other's.
     */
    public static function context(): string
    {
        $value = config('sentinel.context');

        if ($value === null) {
            return '';
        }

        if (! is_string($value) || ! mb_check_encoding($value, 'UTF-8') || strlen($value) > 255) {
            throw InvalidSentinelConfigurationException::invalidValue('context', 'must be a UTF-8 string of at most 255 bytes');
        }

        return $value;
    }
}
