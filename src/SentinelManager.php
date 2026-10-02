<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Closure;
use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Sentinel\Accessors\KeysAccessor;
use RoundlyConsulting\Sentinel\Actions\ExampleSentinelAction;
use RoundlyConsulting\Sentinel\Actions\Keys\GenerateKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\RetireKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\RevokeKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\RotateKeyAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\ExampleSentinelData;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * The public API behind the `Sentinel` facade, injectable by its own class-string. Every
 * method is thin: it resolves an action through the container and calls `execute()`, so host
 * overrides and `Sentinel::fake()` both apply. Sub-accessors and model traits call back into
 * this manager, never into an action.
 *
 * Not Laravel\Sentinel\SentinelManager (laravel/sentinel, pulled in by Horizon/Pulse/Telescope)
 * — import RoundlyConsulting\Sentinel\SentinelManager.
 *
 * Not final on purpose: SentinelFake extends it, so an injected manager still type-checks
 * under `Sentinel::fake()`.
 */
class SentinelManager
{
    public function __construct(
        protected readonly Container $container,
    ) {}

    /**
     * REPLACE ME — the template placeholder; removed in Phase D with the first seal verb.
     */
    public function example(ExampleSentinelData $data): string
    {
        return $this->container->make(ExampleSentinelAction::class)->execute($data);
    }

    // ── keys ──────────────────────────────────────────────────────────────────

    public function keys(): KeysAccessor
    {
        return new KeysAccessor($this);
    }

    public function generateKey(GenerateKeyRequest $request): GeneratedKey
    {
        return $this->container->make(GenerateKeyAction::class)->execute($request);
    }

    public function rotateKey(RotateKeyRequest $request): RotationResult
    {
        return $this->container->make(RotateKeyAction::class)->execute($request);
    }

    public function revokeKey(RevokeKeyRequest $request): KeyInfo
    {
        return $this->container->make(RevokeKeyAction::class)->execute($request);
    }

    public function retireKey(string $ring, string $keyId): KeyInfo
    {
        return $this->container->make(RetireKeyAction::class)->execute($ring, $keyId);
    }

    /**
     * @return list<KeyInfo>
     */
    public function listKeys(?string $ring = null): array
    {
        if ($ring !== null) {
            Settings::ring($ring);
        }

        return $this->container->make(KeyStoreManager::class)->all($ring);
    }

    public function findKey(string $ring, string $keyId): ?KeyInfo
    {
        $key = $this->container->make(KeyStoreManager::class)->find($ring, $keyId);

        return $key === null ? null : KeyInfo::fromKey($key);
    }

    /**
     * The current signing key of a ring (null = the default ring).
     */
    public function currentKey(?string $ring = null): KeyInfo
    {
        return KeyInfo::fromKey($this->container->make(KeyStoreManager::class)->signingKey($ring ?? Settings::defaultRing()));
    }

    /**
     * Register a custom key-store driver: `fn (Container $app, string $ring, array $config): KeyStore`.
     */
    public function extend(string $driver, Closure $factory): static
    {
        $this->container->make(KeyStoreManager::class)->extend($driver, $factory);

        return $this;
    }
}
