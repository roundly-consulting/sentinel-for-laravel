<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Tests\Transitive;

use Illuminate\Support\ServiceProvider;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * A host that gets Sentinel only as another package's dependency (cosmos-logging requires it
 * to verify MACs): the provider is auto-discovered and the shipped defaults apply, but the
 * host never published Sentinel's config or migrations — none of its tables exist.
 */
abstract class TransitiveHostTestCase extends TestCase
{
    /** @return list<class-string<ServiceProvider>|string> */
    protected function migrationSources(): array
    {
        return [];
    }

    /** @return array<string, mixed> */
    protected function configBeforeBoot(): array
    {
        // No Sentinel key and no Sentinel setting: only what any Laravel app has.
        return [
            'app.key' => 'base64:ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=',
            'app.timezone' => 'Europe/Bratislava',
        ];
    }
}
