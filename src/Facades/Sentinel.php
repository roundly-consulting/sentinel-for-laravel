<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Facades;

use Closure;
use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Sentinel\Accessors\KeysAccessor;
use RoundlyConsulting\Sentinel\DataTransferObjects\ExampleSentinelData;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\RecordedCall;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;

/**
 * Import this class explicitly — Sentinel registers **no** global alias (cartalyst/sentinel
 * owns the global `Sentinel`, laravel/sentinel ships `Laravel\Sentinel\Sentinel`).
 *
 * @method static string example(ExampleSentinelData $data)
 * @method static KeysAccessor keys()
 * @method static GeneratedKey generateKey(GenerateKeyRequest $request)
 * @method static RotationResult rotateKey(RotateKeyRequest $request)
 * @method static KeyInfo revokeKey(RevokeKeyRequest $request)
 * @method static KeyInfo retireKey(string $ring, string $keyId)
 * @method static list<KeyInfo> listKeys(string|null $ring = null)
 * @method static KeyInfo|null findKey(string $ring, string $keyId)
 * @method static KeyInfo currentKey(string|null $ring = null)
 * @method static SentinelManager extend(string $driver, Closure $factory)
 * @method static void assertExampleCalled(Closure|null $callback = null)
 * @method static void assertNothingCalled()
 * @method static void assertKeyGenerated(string|null $ring = null)
 * @method static void assertKeyRotated(string|null $ring = null)
 * @method static void assertKeyRevoked(string $keyId)
 * @method static void assertNoKeyChanges()
 * @method static list<RecordedCall> recorded(string|null $method = null)
 *
 * @see SentinelManager
 */
final class Sentinel extends Facade
{
    /**
     * Swap the manager for a recording fake — behind the facade and in the container, so an
     * injected SentinelManager is faked too.
     */
    public static function fake(): SentinelFake
    {
        $fake = app(SentinelFake::class);

        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return SentinelManager::class;
    }
}
