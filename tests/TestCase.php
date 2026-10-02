<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Sentinel\SentinelServiceProvider;
use RoundlyConsulting\Testing\PackageTestCase;

abstract class TestCase extends PackageTestCase
{
    /** @return list<class-string<ServiceProvider>> */
    protected function packageProviders(): array
    {
        return [SentinelServiceProvider::class];
    }

    // No migrationSources() override — the base case defaults to []. Add one once the
    // package ships migrations: return [SentinelServiceProvider::class] (never a
    // literal filename) once ->hasMigrations() is wired in the provider.
}
