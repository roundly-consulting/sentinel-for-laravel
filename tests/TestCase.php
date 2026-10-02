<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Sentinel\SentinelServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;

abstract class TestCase extends PackageTestCase
{
    /** The deterministic test root key of the default ring: bytes 0x01…0x20. */
    public const string ROOT_KEY = 'base64:AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=';

    public const string ROOT_KEY_ID = 'test-default';

    private string $timezone = 'UTC';

    protected function setUp(): void
    {
        parent::setUp();

        // Fleet theme 3: run with a non-UTC process zone, so any local-time leak into storage
        // or a MAC shows up as a failure instead of passing by coincidence.
        $this->timezone = date_default_timezone_get();
        date_default_timezone_set('Europe/Bratislava');
    }

    protected function tearDown(): void
    {
        date_default_timezone_set($this->timezone);

        parent::tearDown();
    }

    /** @return list<class-string<ServiceProvider>> */
    protected function packageProviders(): array
    {
        return [SentinelServiceProvider::class];
    }

    /** @return list<class-string<ServiceProvider>|string> */
    protected function migrationSources(): array
    {
        return [SentinelServiceProvider::class, __DIR__.'/Fixtures/migrations'];
    }

    /** @return array<string, mixed> */
    protected function configBeforeBoot(): array
    {
        return [
            'app.key' => 'base64:ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=',
            'app.timezone' => 'Europe/Bratislava',
            'sentinel.keys.rings.default.key_id' => self::ROOT_KEY_ID,
            'sentinel.keys.rings.default.key' => self::ROOT_KEY,
        ];
    }
}
