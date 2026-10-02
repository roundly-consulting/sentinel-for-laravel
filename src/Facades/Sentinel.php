<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Facades;

use Illuminate\Support\Facades\Facade;
use RoundlyConsulting\Sentinel\DataTransferObjects\ExampleSentinelData;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;

/**
 * Keep one `@method static` line per public manager method — FacadeTest's
 * `toDocumentItsRoot()` fails on a missing, stale or miscounted line.
 *
 * @method static string example(ExampleSentinelData $data)
 * @method static void assertExampleCalled(\Closure|null $callback = null)
 * @method static void assertNothingCalled()
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
