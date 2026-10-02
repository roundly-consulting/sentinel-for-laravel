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

    public static function unknownDriver(string $key, string $driver): self
    {
        $shown = preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $driver) === 1 ? $driver : '(invalid)';

        return self::invalidValue($key, "names an unknown key driver [{$shown}]; use config, database, chain or one registered with Sentinel::extend()");
    }

    public static function invalidAlgorithmList(string $key): self
    {
        return self::invalidValue($key, 'must be a non-empty list of supported algorithm names (hmac-sha256, hmac-sha384, hmac-sha512, ed25519, ecdsa-p256-sha256, ecdsa-p384-sha384)');
    }

    public static function invalidPreviousKey(string $key, int $position): self
    {
        return self::invalidValue($key, "entry #{$position} must be \"kid|algorithm|base64:material\"");
    }
}
