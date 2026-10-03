<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\PackageToolkit\Support\Config;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Idempotency\RunLimits;
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

        if (in_array($value, self::signatureRings(), true)) {
            throw InvalidSentinelConfigurationException::invalidValue('keys.default_ring', 'must not be a ring HTTP message signatures use (a partner\'s key would vouch for seals)');
        }

        return $value;
    }

    /**
     * The rings HTTP message signatures use — every profile's and the outbound one. They hold
     * partners' keys (and secrets partners know), so no seal, ledger entry or checkpoint may
     * ever be vouched for by one of them.
     *
     * @return list<string>
     */
    public static function signatureRings(): array
    {
        $profiles = config('sentinel.signatures.profiles');
        $rings = [config('sentinel.signatures.outbound.ring') ?? 'http'];

        foreach (is_array($profiles) ? $profiles : [] as $profile) {
            $rings[] = is_array($profile) ? ($profile['ring'] ?? 'http') : 'http';
        }

        return array_values(array_unique(array_filter($rings, is_string(...))));
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

        if (in_array($ring, self::signatureRings(), true)) {
            throw InvalidSentinelConfigurationException::invalidValue('ledger.ring', 'must not be a ring HTTP message signatures use (a partner\'s key would vouch for the ledger)');
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

    /**
     * `database`, `cache`, or a host binding of the store contract (any other name).
     */
    public static function idempotencyStore(): string
    {
        return self::storeName('idempotency.store', config('sentinel.idempotency.store'));
    }

    public static function idempotencyCacheStore(): ?string
    {
        return self::optionalString('idempotency.cache_store', config('sentinel.idempotency.cache_store'));
    }

    public static function idempotencyHeader(): string
    {
        return self::headerName('idempotency.header', config('sentinel.idempotency.header') ?? 'Idempotency-Key');
    }

    public static function replayHeader(): string
    {
        return self::headerName('idempotency.replay_header', config('sentinel.idempotency.replay_header') ?? 'Idempotent-Replayed');
    }

    /**
     * @return list<string>
     */
    public static function idempotencyMethods(): array
    {
        $methods = config('sentinel.idempotency.methods') ?? ['POST', 'PATCH'];

        if (! is_array($methods) || ! array_is_list($methods) || $methods === []) {
            throw InvalidSentinelConfigurationException::invalidValue('idempotency.methods', 'must be a non-empty list of HTTP methods');
        }

        $normalized = [];

        foreach ($methods as $method) {
            if (! is_string($method) || preg_match('/^[A-Za-z]{1,16}$/D', $method) !== 1) {
                throw InvalidSentinelConfigurationException::invalidValue('idempotency.methods', 'must be a non-empty list of HTTP methods');
            }

            $normalized[] = strtoupper($method);
        }

        return $normalized;
    }

    public static function idempotencyTtl(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.idempotency.ttl', RunLimits::MIN_TTL, RunLimits::MAX_TTL, 86400);
    }

    public static function idempotencyLockSeconds(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.idempotency.lock_seconds', 1, 3600, 60);
    }

    public static function idempotencyMinLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.idempotency.min_length', 1, 255, 16);
    }

    public static function idempotencyMaxLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.idempotency.max_length', 1, 255, 255);
    }

    public static function idempotencyAcceptsUnquoted(): bool
    {
        return Config::boolean('sentinel.idempotency.accept_unquoted', true);
    }

    public static function storesClientErrors(): bool
    {
        return Config::boolean('sentinel.idempotency.store_client_errors', true);
    }

    public static function storesServerErrors(): bool
    {
        return Config::boolean('sentinel.idempotency.store_server_errors', false);
    }

    /**
     * The handler and the record commit in one database transaction — which only a store
     * writing to that database takes part in: a cache record is not rolled back when the
     * COMMIT fails, and its completed response would be replayed for work that never happened.
     */
    public static function idempotencyTransactional(): bool
    {
        $transactional = Config::boolean('sentinel.idempotency.transactional', false);

        if ($transactional && self::idempotencyStore() !== 'database') {
            throw InvalidSentinelConfigurationException::invalidValue('idempotency.transactional', 'needs idempotency.store = database — a cache record is not rolled back with the transaction');
        }

        return $transactional;
    }

    public static function idempotencyEncrypt(): bool
    {
        return Config::boolean('sentinel.idempotency.encrypt', true);
    }

    public static function maxResponseBytes(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.idempotency.max_response_bytes', 1024, 67108864, 1048576);
    }

    /**
     * Lowercase header names a replay carries; `set-cookie` never.
     *
     * @return list<string>
     */
    public static function replayedHeaders(): array
    {
        $headers = config('sentinel.idempotency.replayed_headers') ?? [];

        if (! is_array($headers) || ! array_is_list($headers)) {
            throw InvalidSentinelConfigurationException::invalidValue('idempotency.replayed_headers', 'must be a list of header names');
        }

        $names = [];

        foreach ($headers as $header) {
            if (! is_string($header) || preg_match('/^[A-Za-z0-9-]{1,64}$/D', $header) !== 1) {
                throw InvalidSentinelConfigurationException::invalidValue('idempotency.replayed_headers', 'must be a list of header names');
            }

            $names[] = strtolower($header);
        }

        return array_values(array_diff(array_unique($names), ['set-cookie']));
    }

    public static function nonceStore(): string
    {
        return self::storeName('nonces.store', config('sentinel.nonces.store'));
    }

    public static function nonceCacheStore(): ?string
    {
        return self::optionalString('nonces.cache_store', config('sentinel.nonces.cache_store'));
    }

    public static function nonceTtl(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.nonces.ttl', 1, 2592000, 900);
    }

    public static function nonceLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.nonces.length', 32, 128, 43);
    }

    public static function problemTypeBase(): ?string
    {
        $base = self::optionalString('problems.type_base', config('sentinel.problems.type_base'));

        if ($base !== null && filter_var($base, FILTER_VALIDATE_URL) === false) {
            throw InvalidSentinelConfigurationException::invalidValue('problems.type_base', 'must be an absolute URL or null');
        }

        return $base;
    }

    private static function storeName(string $key, mixed $store): string
    {
        $store ??= 'database';

        if (! is_string($store) || preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $store) !== 1) {
            throw InvalidSentinelConfigurationException::invalidValue($key, 'must be database, cache or the name of a bound store');
        }

        return $store;
    }

    private static function optionalString(string $key, mixed $value): ?string
    {

        if ($value !== null && ! is_string($value)) {
            throw InvalidSentinelConfigurationException::invalidValue($key, 'must be a string or null');
        }

        return $value === null || $value === '' ? null : $value;
    }

    private static function headerName(string $key, mixed $value): string
    {

        if (! is_string($value) || preg_match('/^[A-Za-z0-9-]{1,64}$/D', $value) !== 1) {
            throw InvalidSentinelConfigurationException::invalidValue($key, 'must be an HTTP header name');
        }

        return $value;
    }

    public static function outboundRing(): string
    {
        $ring = config('sentinel.signatures.outbound.ring') ?? 'http';

        if (! is_string($ring) || ! in_array($ring, self::rings(), true)) {
            throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.ring', 'must name a configured key ring');
        }

        return $ring;
    }

    public static function outboundLabel(): string
    {
        $label = config('sentinel.signatures.outbound.label') ?? 'sig1';

        if (! is_string($label) || ! ProfileResolver::isLabel($label)) {
            throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.label', 'must be a signature label ([a-z*][a-z0-9_-.*]*)');
        }

        return $label;
    }

    /**
     * @return list<string>
     */
    public static function outboundComponents(): array
    {
        $components = ProfileResolver::components('signatures.outbound.components', config('sentinel.signatures.outbound.components') ?? []);

        // A signature that covers nothing authenticates no part of the request.
        return $components !== [] ? $components : throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.components', 'must name at least one component');
    }

    public static function outboundDigest(): DigestAlgorithm
    {
        return Config::using(InvalidSentinelConfigurationException::class)->enum('sentinel.signatures.outbound.digest', DigestAlgorithm::class);
    }

    public static function outboundExpiresIn(): ?int
    {
        return config('sentinel.signatures.outbound.expires_in') === null
            ? null
            : Config::using(InvalidSentinelConfigurationException::class)->intBetween('sentinel.signatures.outbound.expires_in', 1, 86400, 300);
    }

    public static function outboundTag(): ?string
    {
        $tag = config('sentinel.signatures.outbound.tag');

        if ($tag !== null && (! is_string($tag) || ! ProfileResolver::isTag($tag))) {
            throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.tag', 'must be a printable ASCII string or null');
        }

        return $tag;
    }

    public static function outboundIncludesAlg(): bool
    {
        return Config::boolean('sentinel.signatures.outbound.include_alg', false);
    }

    public static function advertisesSignatures(): bool
    {
        return Config::boolean('sentinel.signatures.advertise', true);
    }

    /**
     * Whether Sentinel registers its upkeep tasks on the scheduler.
     */
    public static function scheduleEnabled(): bool
    {
        return Config::boolean('sentinel.schedule.enabled', true);
    }

    /**
     * The scheduler frequency method of one upkeep task (`checkpoint`, `verify`, `prune`), or
     * null when the task is off.
     */
    public static function scheduleFrequency(string $task): ?string
    {
        // Literal keys: each one is read (and pinned by the config contract) on its own.
        $value = match ($task) {
            'checkpoint' => config('sentinel.schedule.checkpoint'),
            'verify' => config('sentinel.schedule.verify'),
            'prune' => config('sentinel.schedule.prune'),
            default => throw InvalidSentinelConfigurationException::invalidValue('schedule', "has no task [{$task}]"),
        };

        if ($value === null || $value === '' || $value === 'off') {
            return null;
        }

        if (! is_string($value) || ! in_array($value, self::FREQUENCIES, true)) {
            throw InvalidSentinelConfigurationException::invalidValue("schedule.{$task}", 'must be off or one of '.implode(', ', self::FREQUENCIES));
        }

        return $value;
    }

    /** The scheduler frequencies an upkeep task may run at. */
    public const array FREQUENCIES = [
        'everyMinute', 'everyTwoMinutes', 'everyFiveMinutes', 'everyTenMinutes', 'everyFifteenMinutes', 'everyThirtyMinutes',
        'hourly', 'everyTwoHours', 'everyThreeHours', 'everyFourHours', 'everySixHours', 'daily', 'weekly',
    ];
}
