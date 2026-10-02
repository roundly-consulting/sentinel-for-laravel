<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Reads and validates inbound signature profiles (`sentinel.signatures.profiles.<name>`);
 * an invalid profile fails loudly with its key, never with a lenient default.
 *
 * @internal
 */
final class ProfileResolver
{
    public static function resolve(?string $name = null): SignatureProfile
    {
        $name ??= self::defaultProfile();
        $profiles = config('sentinel.signatures.profiles');

        if (! is_array($profiles) || ! is_array($profiles[$name] ?? null) || preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $name) !== 1) {
            throw InvalidSentinelConfigurationException::unknownProfile($name);
        }

        $prefix = "signatures.profiles.{$name}";
        $ring = config("sentinel.signatures.profiles.{$name}.ring") ?? 'http';
        $label = config("sentinel.signatures.profiles.{$name}.label");
        $tag = config("sentinel.signatures.profiles.{$name}.tag");

        if (! is_string($ring) || ! in_array($ring, Settings::rings(), true)) {
            throw InvalidSentinelConfigurationException::invalidValue("{$prefix}.ring", 'must name a configured key ring');
        }

        if ($label !== null && (! is_string($label) || ! self::isLabel($label))) {
            throw InvalidSentinelConfigurationException::invalidValue("{$prefix}.label", 'must be a signature label ([a-z*][a-z0-9_-.*]*) or null');
        }

        if ($tag !== null && (! is_string($tag) || preg_match('/^[\x20-\x7E]{1,255}$/D', $tag) !== 1)) {
            throw InvalidSentinelConfigurationException::invalidValue("{$prefix}.tag", 'must be a printable ASCII string or null');
        }

        return new SignatureProfile(
            $name,
            $ring,
            is_string($label) ? $label : null,
            is_string($tag) ? $tag : null,
            self::components("{$prefix}.components", config("sentinel.signatures.profiles.{$name}.components") ?? []),
            Config::boolean("sentinel.signatures.profiles.{$name}.require_query", true),
            Config::boolean("sentinel.signatures.profiles.{$name}.require_content_digest", true),
            Config::boolean("sentinel.signatures.profiles.{$name}.require_nonce", true),
            self::seconds("{$prefix}.max_age", config("sentinel.signatures.profiles.{$name}.max_age"), 1, 86400, 300),
            self::seconds("{$prefix}.clock_skew", config("sentinel.signatures.profiles.{$name}.clock_skew"), 0, 3600, 30),
            self::algorithms("{$prefix}.algorithms", config("sentinel.signatures.profiles.{$name}.algorithms")),
        );
    }

    public static function defaultProfile(): string
    {
        $name = config('sentinel.signatures.default_profile') ?? 'default';

        return is_string($name) ? $name : throw InvalidSentinelConfigurationException::invalidValue('signatures.default_profile', 'must be a profile name');
    }

    /**
     * @return list<string>
     */
    public static function components(string $key, mixed $components): array
    {
        if (! is_array($components) || ! array_is_list($components)) {
            throw InvalidSentinelConfigurationException::invalidValue($key, 'must be a list of component names');
        }

        $names = [];

        foreach ($components as $component) {
            if (! is_string($component) || $component === '' || strtolower($component) !== $component || ! ComponentResolver::supported($component)) {
                throw InvalidSentinelConfigurationException::invalidValue($key, 'must be a list of lowercase, supported component names');
            }

            $names[] = $component;
        }

        return array_values(array_unique($names));
    }

    private static function seconds(string $key, mixed $value, int $minimum, int $maximum, int $default): int
    {
        $value ??= $default;
        $seconds = is_int($value) ? $value : (is_string($value) && preg_match('/^\d{1,6}$/D', $value) === 1 ? (int) $value : null);

        if ($seconds === null || $seconds < $minimum || $seconds > $maximum) {
            throw InvalidSentinelConfigurationException::invalidValue($key, "must be an integer between {$minimum} and {$maximum}");
        }

        return $seconds;
    }

    /**
     * @return list<Algorithm>
     */
    private static function algorithms(string $key, mixed $configured): array
    {
        if (! is_array($configured) || ! array_is_list($configured) || $configured === []) {
            throw InvalidSentinelConfigurationException::invalidAlgorithmList($key);
        }

        $algorithms = [];

        foreach ($configured as $name) {
            $algorithm = is_string($name) ? Algorithm::tryFrom($name) : null;

            if ($algorithm === null || ! $algorithm->isHttpRegistered()) {
                throw InvalidSentinelConfigurationException::invalidValue($key, 'must list RFC 9421 algorithms (hmac-sha256, ed25519, ecdsa-p256-sha256, ecdsa-p384-sha384)');
            }

            $algorithms[$algorithm->value] = $algorithm;
        }

        return array_values($algorithms);
    }

    /**
     * Signature labels are structured-field dictionary keys.
     */
    public static function isLabel(string $label): bool
    {
        return preg_match('/^[a-z*][a-z0-9_\-.*]{0,63}$/D', $label) === 1;
    }
}
