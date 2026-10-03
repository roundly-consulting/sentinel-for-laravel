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
 * on a security-relevant key. A key that is not set — absent, null or blank (`''` or
 * whitespace, what a host's `SENTINEL_X=` gives) — takes its shipped default. Booleans go
 * through the toolkit's boolean reader, which is strict (`SENTINEL_X=off` means off,
 * `SENTINEL_X=disabled` throws — a typo never reads as the default), integers through its
 * range checks.
 */
final class Settings
{
    /**
     * A strict boolean (the toolkit's `boolean()` reader): `true`/`false`, `on`/`off`, `yes`/`no`, `1`/`0`
     * (any case); not set — absent, null or blank (`''`, a host's `SENTINEL_X=`) — is the
     * default, and anything else throws instead of silently reading as the default
     * (`SENTINEL_ALLOW_SUSPENSION=disabled` must never leave suspension on). Callers read the
     * value with `config()` themselves, so the key stays visible to the config contract.
     *
     * @param  string  $key  the key under `sentinel.`, for the error message
     */
    public static function flag(string $key, mixed $value, bool $default): bool
    {
        return Config::for(["sentinel.{$key}" => $value], InvalidSentinelConfigurationException::class)->boolean("sentinel.{$key}", $default);
    }

    /**
     * The value, or null when it is not set: a blank string (`''` or whitespace — what a
     * host's `SENTINEL_X=` puts in config) means the same as an absent key, so the caller's
     * default applies.
     */
    public static function nullIfBlank(mixed $value): mixed
    {
        return is_string($value) && trim($value) === '' ? null : $value;
    }

    /**
     * The application context bound into every MAC (`sentinel.context`). Changing it
     * invalidates every seal, by design: two apps sharing keys cannot forge each other's.
     */
    public static function context(): string
    {
        $value = self::nullIfBlank(config('sentinel.context'));

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
        $value = self::nullIfBlank(config('sentinel.database.connection'));

        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw InvalidSentinelConfigurationException::invalidValue('database.connection', 'must be a connection name or null');
        }

        return $value;
    }

    public static function defaultRing(): string
    {
        $value = self::nullIfBlank(config('sentinel.keys.default_ring')) ?? 'default';

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
        $profiles = config('sentinel.signatures.profiles') ?? [];
        $rings = [self::nullIfBlank(config('sentinel.signatures.outbound.ring')) ?? 'http'];

        if (! is_array($profiles)) {
            throw InvalidSentinelConfigurationException::invalidValue('signatures.profiles', 'must be an array of profiles');
        }

        foreach ($profiles as $name => $profile) {
            $rings[] = is_array($profile) ? (self::nullIfBlank($profile['ring'] ?? null) ?? 'http') : null;

            // A ring that is not a name cannot be checked against the sealing rings, so it
            // is refused rather than skipped (skipping it would let a partner ring vouch).
            if (! is_string(end($rings))) {
                throw InvalidSentinelConfigurationException::invalidValue("signatures.profiles.{$name}.ring", 'must name a configured key ring');
            }
        }

        if (! is_string($rings[0])) {
            throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.ring', 'must name a configured key ring');
        }

        /** @var list<string> $rings */
        return array_values(array_unique($rings));
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

        // Not set (absent, null or blank) reads as the default — or, for the driver, as missing.
        $driver = self::nullIfBlank(config("sentinel.keys.rings.{$ring}.driver"));
        $algorithms = config("sentinel.keys.rings.{$ring}.algorithms");
        $keyId = self::nullIfBlank(config("sentinel.keys.rings.{$ring}.key_id"));
        $algorithm = self::nullIfBlank(config("sentinel.keys.rings.{$ring}.algorithm")) ?? Algorithm::HmacSha256->value;
        $key = self::nullIfBlank(config("sentinel.keys.rings.{$ring}.key"));
        $publicKey = self::nullIfBlank(config("sentinel.keys.rings.{$ring}.public_key"));
        $previous = self::nullIfBlank(config("sentinel.keys.rings.{$ring}.previous")) ?? '';
        $drivers = config("sentinel.keys.rings.{$ring}.drivers") ?? ['config', 'database'];

        if (! is_string($driver)) {
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
            $keyId,
            $pinned,
            $key,
            $publicKey,
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
        return self::flag('sealing.auto', config('sentinel.sealing.auto'), true);
    }

    public static function allowSuspension(): bool
    {
        return self::flag('sealing.allow_suspension', config('sentinel.sealing.allow_suspension'), true);
    }

    public static function fieldTags(): bool
    {
        return self::flag('sealing.field_tags', config('sentinel.sealing.field_tags'), true);
    }

    public static function onTamperedWrite(): TamperedWritePolicy
    {
        return Config::using(InvalidSentinelConfigurationException::class)->enum('sentinel.sealing.on_tampered_write', TamperedWritePolicy::class, TamperedWritePolicy::Refuse);
    }

    public static function reasonMaxLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.sealing.reason_max_length', 1000, min: 1, max: 10000);
    }

    /**
     * @return int<1, max>
     */
    public static function transactionAttempts(): int
    {
        return max(1, Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.sealing.transaction_attempts', 3, min: 1, max: 10));
    }

    public static function checkLedger(): bool
    {
        return self::flag('verification.check_ledger', config('sentinel.verification.check_ledger'), true);
    }

    public static function outdatedIsIntact(): bool
    {
        return self::flag('verification.outdated_is_intact', config('sentinel.verification.outdated_is_intact'), true);
    }

    public static function logChannel(): ?string
    {
        return self::optionalString('verification.log_channel', config('sentinel.verification.log_channel'));
    }

    public static function acknowledgementAbility(): ?string
    {
        return self::optionalString('acknowledgement.ability', config('sentinel.acknowledgement.ability'));
    }

    public static function ledgerEnabled(): bool
    {
        return self::flag('ledger.enabled', config('sentinel.ledger.enabled'), true);
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
        $ring = self::nullIfBlank(config('sentinel.ledger.ring')) ?? self::defaultRing();

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

            // One database once: null and the default connection's own name are the same one,
            // and counting it twice would double every count and every finding.
            $resolved = $connection ?? (string) config('database.default');

            if (! array_key_exists($resolved, $names)) {
                $names[$resolved] = $connection;
            }
        }

        return array_values($names);
    }

    public static function ledgerBatchSize(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.ledger.batch_size', 1000, min: 1, max: 100000);
    }

    public static function backlogWarningSeconds(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.ledger.backlog_warning_seconds', 600, min: 60, max: 86400);
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
        return Config::using(InvalidSentinelConfigurationException::class)->enum('sentinel.verification.retrieve_reaction', Reaction::class, Reaction::Throw);
    }

    public static function retrieveChecksLedger(): bool
    {
        return self::flag('verification.retrieve_checks_ledger', config('sentinel.verification.retrieve_checks_ledger'), false);
    }

    public static function verifiedStatus(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.middleware.verified_status', 409, min: 400, max: 599);
    }

    /**
     * Whether `sentinel.verified` aborts (`abort`, the default) or only reports (`report`).
     */
    public static function verifiedAborts(): bool
    {
        $reaction = self::nullIfBlank(config('sentinel.middleware.verified_reaction')) ?? 'abort';

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
        return self::headerName('idempotency.header', self::nullIfBlank(config('sentinel.idempotency.header')) ?? 'Idempotency-Key');
    }

    public static function replayHeader(): string
    {
        return self::headerName('idempotency.replay_header', self::nullIfBlank(config('sentinel.idempotency.replay_header')) ?? 'Idempotent-Replayed');
    }

    /**
     * @return list<string>
     */
    public static function idempotencyMethods(): array
    {
        $methods = self::nullIfBlank(config('sentinel.idempotency.methods')) ?? ['POST', 'PATCH'];

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
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.idempotency.ttl', 86400, min: RunLimits::MIN_TTL, max: RunLimits::MAX_TTL);
    }

    public static function idempotencyLockSeconds(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.idempotency.lock_seconds', 60, min: 1, max: 3600);
    }

    public static function idempotencyMinLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.idempotency.min_length', 16, min: 1, max: 255);
    }

    public static function idempotencyMaxLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.idempotency.max_length', 255, min: 1, max: 255);
    }

    public static function idempotencyAcceptsUnquoted(): bool
    {
        return self::flag('idempotency.accept_unquoted', config('sentinel.idempotency.accept_unquoted'), true);
    }

    public static function storesClientErrors(): bool
    {
        return self::flag('idempotency.store_client_errors', config('sentinel.idempotency.store_client_errors'), true);
    }

    public static function storesServerErrors(): bool
    {
        return self::flag('idempotency.store_server_errors', config('sentinel.idempotency.store_server_errors'), false);
    }

    /**
     * The handler and the record commit in one database transaction — which only a store
     * writing to that database takes part in: a cache record is not rolled back when the
     * COMMIT fails, and its completed response would be replayed for work that never happened.
     */
    public static function idempotencyTransactional(): bool
    {
        $transactional = self::flag('idempotency.transactional', config('sentinel.idempotency.transactional'), false);

        if ($transactional && self::idempotencyStore() !== 'database') {
            throw InvalidSentinelConfigurationException::invalidValue('idempotency.transactional', 'needs idempotency.store = database — a cache record is not rolled back with the transaction');
        }

        return $transactional;
    }

    public static function idempotencyEncrypt(): bool
    {
        return self::flag('idempotency.encrypt', config('sentinel.idempotency.encrypt'), true);
    }

    public static function maxResponseBytes(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.idempotency.max_response_bytes', 1048576, min: 1024, max: 67108864);
    }

    /**
     * Lowercase header names a replay carries; `set-cookie` never.
     *
     * @return list<string>
     */
    public static function replayedHeaders(): array
    {
        $headers = self::nullIfBlank(config('sentinel.idempotency.replayed_headers')) ?? [];

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
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.nonces.ttl', 900, min: 1, max: 2592000);
    }

    public static function nonceLength(): int
    {
        return Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.nonces.length', 43, min: 32, max: 128);
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
        $store = self::nullIfBlank($store) ?? 'database';

        if (! is_string($store) || preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $store) !== 1) {
            throw InvalidSentinelConfigurationException::invalidValue($key, 'must be database, cache or the name of a bound store');
        }

        return $store;
    }

    /**
     * A string or null: not set — absent, null or blank (an empty env value) — reads as
     * null, and anything that is not a string throws rather than silently reading as null.
     */
    public static function optionalString(string $key, mixed $value): ?string
    {
        if ($value !== null && ! is_string($value)) {
            throw InvalidSentinelConfigurationException::invalidValue($key, 'must be a string or null');
        }

        return $value === null || trim($value) === '' ? null : $value;
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
        $ring = self::nullIfBlank(config('sentinel.signatures.outbound.ring')) ?? 'http';

        if (! is_string($ring) || ! in_array($ring, self::rings(), true)) {
            throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.ring', 'must name a configured key ring');
        }

        return $ring;
    }

    public static function outboundLabel(): string
    {
        $label = self::nullIfBlank(config('sentinel.signatures.outbound.label')) ?? 'sig1';

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
        $components = ProfileResolver::components('signatures.outbound.components', self::nullIfBlank(config('sentinel.signatures.outbound.components')) ?? []);

        // A signature that covers nothing authenticates no part of the request.
        return $components !== [] ? $components : throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.components', 'must name at least one component');
    }

    public static function outboundDigest(): DigestAlgorithm
    {
        return Config::using(InvalidSentinelConfigurationException::class)->enum('sentinel.signatures.outbound.digest', DigestAlgorithm::class, DigestAlgorithm::Sha256);
    }

    public static function outboundExpiresIn(): ?int
    {
        // Not set (absent, null or blank) is no expiry, never the 300-second fallback.
        return self::nullIfBlank(config('sentinel.signatures.outbound.expires_in')) === null
            ? null
            : Config::using(InvalidSentinelConfigurationException::class)->integer('sentinel.signatures.outbound.expires_in', 300, min: 1, max: 86400);
    }

    public static function outboundTag(): ?string
    {
        $tag = self::nullIfBlank(config('sentinel.signatures.outbound.tag'));

        if ($tag !== null && (! is_string($tag) || ! ProfileResolver::isTag($tag))) {
            throw InvalidSentinelConfigurationException::invalidValue('signatures.outbound.tag', 'must be a printable ASCII string or null');
        }

        return $tag;
    }

    public static function outboundIncludesAlg(): bool
    {
        return self::flag('signatures.outbound.include_alg', config('sentinel.signatures.outbound.include_alg'), false);
    }

    public static function advertisesSignatures(): bool
    {
        return self::flag('signatures.advertise', config('sentinel.signatures.advertise'), true);
    }

    /**
     * Whether Sentinel registers its upkeep tasks on the scheduler.
     */
    public static function scheduleEnabled(): bool
    {
        return self::flag('schedule.enabled', config('sentinel.schedule.enabled'), true);
    }

    /**
     * The scheduler frequency method of one upkeep task (`checkpoint`, `verify`, `prune`), or
     * null when the task is off (`off` or null). A blank value is not set, so the task keeps
     * its shipped frequency — an empty `SENTINEL_SCHEDULE_CHECKPOINT=` never silently widens
     * the window in which a rollback goes unseen.
     */
    public static function scheduleFrequency(string $task): ?string
    {
        // Literal keys: each one is read (and pinned by the config contract) on its own.
        [$value, $default] = match ($task) {
            'checkpoint' => [config('sentinel.schedule.checkpoint'), 'everyMinute'],
            'verify' => [config('sentinel.schedule.verify'), 'daily'],
            'prune' => [config('sentinel.schedule.prune'), 'daily'],
            default => throw InvalidSentinelConfigurationException::invalidValue('schedule', "has no task [{$task}]"),
        };

        if ($value === null || $value === 'off') {
            return null;
        }

        $value = self::nullIfBlank($value) ?? $default;

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
