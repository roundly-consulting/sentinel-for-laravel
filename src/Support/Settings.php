<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Keys\RingConfig;

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

    /**
     * The connection of `sentinel_keys`, `sentinel_idempotency_keys` and `sentinel_nonces`
     * (null = the default connection).
     */
    public static function keyConnection(): ?string
    {
        $value = config('sentinel.database.connection');

        if ($value === null || $value === '') {
            return null;
        }

        if (! is_string($value)) {
            throw InvalidSentinelConfigurationException::invalidValue('database.connection', 'must be a connection name or null');
        }

        return $value;
    }

    public static function defaultRing(): string
    {
        $value = config('sentinel.keys.default_ring') ?? 'default';

        if (! is_string($value) || ! Identifiers::isRing($value)) {
            throw InvalidSentinelConfigurationException::invalidValue('keys.default_ring', 'must be a ring name ([a-z][a-z0-9_-]{0,63})');
        }

        return $value;
    }

    /**
     * The configured revocation list (`ring:kid,…`). It overrides every driver, so a key
     * revoked here stays revoked even if a database row is restored from an old backup.
     *
     * @return list<string>
     */
    public static function revokedKeys(): array
    {
        $entries = Identifiers::csv(config('sentinel.keys.revoked'));

        foreach ($entries as $entry) {
            $parts = explode(':', $entry, 2);

            if (count($parts) !== 2 || ! Identifiers::isRing($parts[0]) || ! Identifiers::isKeyId($parts[1])) {
                throw InvalidSentinelConfigurationException::invalidValue('keys.revoked', 'must be a comma-separated list of ring:kid entries');
            }
        }

        return $entries;
    }

    /**
     * The configured ring names.
     *
     * @return list<string>
     */
    public static function rings(): array
    {
        $rings = config('sentinel.keys.rings');

        if (! is_array($rings)) {
            throw InvalidSentinelConfigurationException::invalidValue('keys.rings', 'must be an array of rings');
        }

        $names = array_map(strval(...), array_keys($rings));

        foreach ($names as $name) {
            if (! Identifiers::isRing($name)) {
                throw InvalidSentinelConfigurationException::invalidValue('keys.rings', 'has an invalid ring name; use [a-z][a-z0-9_-]{0,63}');
            }
        }

        return $names;
    }

    public static function ring(string $ring): RingConfig
    {
        if (! in_array($ring, self::rings(), true)) {
            throw SealingMisconfiguredException::unknownRing($ring);
        }

        $driver = config("sentinel.keys.rings.{$ring}.driver");
        $algorithms = config("sentinel.keys.rings.{$ring}.algorithms");
        $keyId = config("sentinel.keys.rings.{$ring}.key_id");
        $algorithm = config("sentinel.keys.rings.{$ring}.algorithm") ?? Algorithm::HmacSha256->value;
        $key = config("sentinel.keys.rings.{$ring}.key");
        $publicKey = config("sentinel.keys.rings.{$ring}.public_key");
        $previous = config("sentinel.keys.rings.{$ring}.previous") ?? '';
        $drivers = config("sentinel.keys.rings.{$ring}.drivers") ?? ['config', 'database'];

        if (! is_string($driver) || $driver === '') {
            throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.driver", 'must be a driver name');
        }

        if ($keyId !== null && (! is_string($keyId) || ! Identifiers::isKeyId($keyId))) {
            throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.key_id", 'must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}');
        }

        $pinned = is_string($algorithm) ? Algorithm::tryFrom($algorithm) : null;

        if ($pinned === null) {
            throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.algorithm", 'must be a supported algorithm name');
        }

        foreach (['key' => $key, 'public_key' => $publicKey] as $name => $value) {
            if ($value !== null && ! is_string($value)) {
                throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.{$name}", 'must be a base64: string or null');
            }
        }

        if (! is_string($previous)) {
            throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.previous", 'must be a comma-separated string');
        }

        return new RingConfig(
            $ring,
            $driver,
            self::algorithms($ring, $algorithms),
            $keyId === '' ? null : $keyId,
            $pinned,
            $key === '' ? null : $key,
            $publicKey === '' ? null : $publicKey,
            $previous,
            self::drivers($ring, $drivers),
        );
    }

    /**
     * @return list<string>
     */
    private static function drivers(string $ring, mixed $configured): array
    {
        $drivers = [];

        foreach (is_array($configured) ? $configured : [null] as $driver) {
            if (! is_string($driver) || $driver === '' || $driver === 'chain') {
                throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.drivers", 'must be a non-empty list of driver names (no nested chain)');
            }

            $drivers[] = $driver;
        }

        return $drivers === [] ? throw InvalidSentinelConfigurationException::invalidValue("keys.rings.{$ring}.drivers", 'must be a non-empty list of driver names (no nested chain)') : $drivers;
    }

    /**
     * @return list<Algorithm>
     */
    private static function algorithms(string $ring, mixed $configured): array
    {
        $key = "keys.rings.{$ring}.algorithms";

        if (! is_array($configured) || $configured === [] || ! array_is_list($configured)) {
            throw InvalidSentinelConfigurationException::invalidAlgorithmList($key);
        }

        $algorithms = [];

        foreach ($configured as $name) {
            $algorithm = (is_string($name) ? Algorithm::tryFrom($name) : null)
                ?? throw InvalidSentinelConfigurationException::invalidAlgorithmList($key);

            $algorithms[$algorithm->value] = $algorithm;
        }

        return array_values($algorithms);
    }
}
