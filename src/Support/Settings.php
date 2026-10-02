<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
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

    public static function autoSeal(): bool
    {
        return Config::boolean('sentinel.sealing.auto', true);
    }

    public static function allowSuspension(): bool
    {
        return Config::boolean('sentinel.sealing.allow_suspension', true);
    }

    public static function fieldTags(): bool
    {
        return Config::boolean('sentinel.sealing.field_tags', true);
    }

    public static function onTamperedWrite(): TamperedWritePolicy
    {
        return Config::using(InvalidSentinelConfigurationException::class)->enum('sentinel.sealing.on_tampered_write', TamperedWritePolicy::class);
    }

    public static function reasonMaxLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.sealing.reason_max_length', 1, 10000, 1000);
    }

    /**
     * @return int<1, max>
     */
    public static function transactionAttempts(): int
    {
        return max(1, Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.sealing.transaction_attempts', 1, 10, 3));
    }

    public static function checkLedger(): bool
    {
        return Config::boolean('sentinel.verification.check_ledger', true);
    }

    public static function outdatedIsIntact(): bool
    {
        return Config::boolean('sentinel.verification.outdated_is_intact', true);
    }

    public static function logChannel(): ?string
    {
        $channel = config('sentinel.verification.log_channel');

        return is_string($channel) && $channel !== '' ? $channel : null;
    }

    public static function acknowledgementAbility(): ?string
    {
        $ability = config('sentinel.acknowledgement.ability');

        return is_string($ability) && $ability !== '' ? $ability : null;
    }

    public static function ledgerEnabled(): bool
    {
        return Config::boolean('sentinel.ledger.enabled', true);
    }

    /**
     * The sealable classes `sentinel:verify` scans when given none.
     *
     * @return list<class-string<Model>>
     */
    public static function models(): array
    {
        $models = config('sentinel.models') ?? [];

        if (! is_array($models) || ! array_is_list($models)) {
            throw InvalidSentinelConfigurationException::invalidValue('models', 'must be a list of model classes');
        }

        $classes = [];

        foreach ($models as $model) {
            if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
                throw InvalidSentinelConfigurationException::invalidValue('models', 'must be a list of model classes');
            }

            $classes[] = $model;
        }

        return $classes;
    }

    /**
     * The ring whose current key signs checkpoints.
     */
    public static function ledgerRing(): string
    {
        $ring = config('sentinel.ledger.ring') ?? self::defaultRing();

        if (! is_string($ring) || ! in_array($ring, self::rings(), true)) {
            throw InvalidSentinelConfigurationException::invalidValue('ledger.ring', 'must name a configured key ring');
        }

        return $ring;
    }

    /**
     * Rings whose keys may have signed a checkpoint (or a ledger entry of a model Sentinel can
     * no longer resolve): the ledger ring and the default ring — never a partner's HTTP ring.
     *
     * @return list<string>
     */
    public static function ledgerRings(): array
    {
        return array_values(array_unique([self::ledgerRing(), self::defaultRing()]));
    }

    /**
     * The connections holding seals and the ledger (null = the default connection).
     *
     * @return list<string|null>
     */
    public static function ledgerConnections(): array
    {
        $connections = config('sentinel.ledger.connections') ?? [null];

        if (! is_array($connections) || ! array_is_list($connections) || $connections === []) {
            throw InvalidSentinelConfigurationException::invalidValue('ledger.connections', 'must be a non-empty list of connection names (null = default)');
        }

        $names = [];

        foreach ($connections as $connection) {
            if ($connection !== null && (! is_string($connection) || $connection === '')) {
                throw InvalidSentinelConfigurationException::invalidValue('ledger.connections', 'must be a non-empty list of connection names (null = default)');
            }

            $names[] = $connection;
        }

        return array_values(array_unique($names));
    }

    public static function ledgerBatchSize(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.ledger.batch_size', 1, 100000, 1000);
    }

    public static function backlogWarningSeconds(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.ledger.backlog_warning_seconds', 60, 86400, 600);
    }

    /**
     * The configured anchor driver names (`SENTINEL_ANCHORS=cache,log`).
     *
     * @return list<string>
     */
    public static function anchors(): array
    {
        $anchors = Identifiers::csv(config('sentinel.ledger.anchors'));

        foreach ($anchors as $anchor) {
            if (preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $anchor) !== 1) {
                throw InvalidSentinelConfigurationException::invalidValue('ledger.anchors', 'must be a comma-separated list of anchor driver names');
            }
        }

        return array_values(array_unique($anchors));
    }

    /**
     * One anchor driver's config section (`sentinel.ledger.anchor_drivers.<name>`).
     *
     * @return array<string, mixed>
     */
    public static function anchorDriver(string $driver): array
    {
        $section = config("sentinel.ledger.anchor_drivers.{$driver}") ?? [];

        if (! is_array($section)) {
            throw InvalidSentinelConfigurationException::invalidValue("ledger.anchor_drivers.{$driver}", 'must be an array');
        }

        $config = [];

        foreach ($section as $key => $value) {
            $config[(string) $key] = $value;
        }

        return $config;
    }

    public static function retrieveReaction(): Reaction
    {
        return Config::using(InvalidSentinelConfigurationException::class)->enum('sentinel.verification.retrieve_reaction', Reaction::class);
    }

    public static function retrieveChecksLedger(): bool
    {
        return Config::boolean('sentinel.verification.retrieve_checks_ledger', false);
    }

    public static function verifiedStatus(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.middleware.verified_status', 400, 599, 409);
    }

    /**
     * Whether `sentinel.verified` aborts (`abort`, the default) or only reports (`report`).
     */
    public static function verifiedAborts(): bool
    {
        $reaction = config('sentinel.middleware.verified_reaction') ?? 'abort';

        return match ($reaction) {
            'abort' => true,
            'report' => false,
            default => throw InvalidSentinelConfigurationException::invalidValue('middleware.verified_reaction', 'must be abort or report'),
        };
    }
}
