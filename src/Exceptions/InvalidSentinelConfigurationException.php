<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * Invalid `config/sentinel.php` values. Thrown at first use, never swallowed: a
 * security-relevant key never falls back to a default silently.
 *
 * The toolkit's `Config::using(self::class)` re-throws its own validation failures as this
 * class (hence the public string constructor inherited from RuntimeException).
 */
final class InvalidSentinelConfigurationException extends SentinelException
{
    public static function invalidValue(string $key, string $expectation): self
    {
        return new self("Configuration value [sentinel.{$key}] {$expectation}.");
    }
}
