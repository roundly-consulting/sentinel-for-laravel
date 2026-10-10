<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Keys\Stores\ChainKeyStore;
use RoundlyConsulting\Sentinel\Keys\Stores\ConfigKeyStore;
use RoundlyConsulting\Sentinel\Keys\Stores\DatabaseKeyStore;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use SensitiveParameter;

/**
 * Resolves rings to key stores. A singleton holding only driver factories (code, never
 * material); the stores themselves — and any decrypted key — live in the scoped
 * {@see KeyCache}, resolved fresh from the container on every call so an Octane worker never
 * pins one request's keys.
 *
 * The configured revocation list is applied here on top of every driver, built-in or custom.
 *
 * @internal
 */
final class KeyStoreManager
{
    /** @var array<string, Closure> */
    private array $drivers = [];

    public function __construct(private readonly Container $container) {}

    /**
     * Register a custom key-store driver: `fn (Container $app, string $ring, array $config): KeyStore`.
     */
    public function extend(string $driver, Closure $factory): void
    {
        $this->drivers[$driver] = $factory;
    }

    public function ring(string $ring): KeyStore
    {
        return $this->cache()->store($ring, fn (): KeyStore => $this->build(Settings::ring($ring)));
    }

    /**
     * The ring's current signing key — Active and holding private/secret material.
     *
     * @throws NoSigningKeyException
     */
    public function signingKey(string $ring): SealingKey
    {
        $key = $this->revocationApplied($this->ring($ring)->signingKey());

        return $key->canSign() ? $key : throw NoSigningKeyException::forRing($ring);
    }

    public function lookup(string $ring, string $keyId): KeyLookup
    {
        $key = $this->ring($ring)->find($keyId);

        if ($key === null) {
            return new KeyLookup(null, $this->cache()->integrityFailed($ring, $keyId) ? KeyLookup::INTEGRITY : KeyLookup::NOT_FOUND);
        }

        return new KeyLookup($this->revocationApplied($key));
    }

    public function find(string $ring, string $keyId): ?SealingKey
    {
        return $this->lookup($ring, $keyId)->key;
    }

    /**
     * @return list<KeyInfo>
     */
    public function all(?string $ring = null): array
    {
        $rings = $ring === null ? Settings::rings() : [$ring];
        $revoked = Settings::revokedKeys();
        $keys = [];

        foreach ($rings as $name) {
            foreach ($this->ring($name)->all() as $info) {
                $keys[] = in_array("{$info->ring}:{$info->keyId}", $revoked, true) && $info->status !== KeyStatus::Revoked
                    ? new KeyInfo($info->ring, $info->keyId, $info->algorithm, KeyStatus::Revoked, $info->driver, false, $info->activatesAt,
                        $info->signsUntil, $info->verifiesUntil, $info->revokedAt, $info->label, $info->ownerType, $info->ownerId)
                    : $info;
            }
        }

        return $keys;
    }

    /**
     * The ring's database store — the only store Sentinel writes keys to.
     *
     * @throws KeyDriverException when the ring has no database driver
     */
    public function writableStore(string $ring): DatabaseKeyStore
    {
        $store = $this->ring($ring);

        foreach ($store instanceof ChainKeyStore ? $store->stores() : [$store] as $candidate) {
            if ($candidate instanceof DatabaseKeyStore) {
                return $candidate;
            }
        }

        throw KeyDriverException::readOnly($ring);
    }

    public function hasWritableStore(string $ring): bool
    {
        try {
            $this->writableStore($ring);

            return true;
        } catch (KeyDriverException) {
            return false;
        }
    }

    /**
     * Drop the loaded stores of this request (after a key write).
     */
    public function flush(): void
    {
        $this->cache()->forget();
    }

    private function build(RingConfig $config): KeyStore
    {
        if ($config->driver !== 'chain') {
            return $this->driver($config->driver, $config, "keys.rings.{$config->name}.driver");
        }

        return new ChainKeyStore($config->name, array_map(
            fn (string $driver): KeyStore => $this->driver($driver, $config, "keys.rings.{$config->name}.drivers"),
            $config->drivers,
        ), Settings::revokedKeys());
    }

    private function driver(string $driver, RingConfig $config, string $configKey): KeyStore
    {
        $revoked = Settings::revokedKeys();

        return match (true) {
            $driver === 'config' => new ConfigKeyStore($config, $revoked, Clock::now()),
            $driver === 'database' => new DatabaseKeyStore(
                $config->name, $revoked, $this->cache(), $this->container->make(Dispatcher::class), $this->container->make(KeyEnvelope::class),
            ),
            isset($this->drivers[$driver]) => $this->custom($driver, $config, $configKey),
            default => throw InvalidSentinelConfigurationException::unknownDriver($configKey, $driver),
        };
    }

    private function custom(string $driver, RingConfig $config, string $configKey): KeyStore
    {
        $section = config("sentinel.keys.rings.{$config->name}");
        $store = ($this->drivers[$driver])($this->container, $config->name, is_array($section) ? $section : []);

        return $store instanceof KeyStore ? $store : throw InvalidSentinelConfigurationException::unknownDriver($configKey, $driver);
    }

    private function revocationApplied(#[SensitiveParameter] SealingKey $key): SealingKey
    {
        return $key->status !== KeyStatus::Revoked && in_array("{$key->ring}:{$key->keyId}", Settings::revokedKeys(), true)
            ? $key->withStatus(KeyStatus::Revoked)
            : $key;
    }

    private function cache(): KeyCache
    {
        return $this->container->make(KeyCache::class);
    }
}
