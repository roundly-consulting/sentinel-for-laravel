<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\PackageToolkit\Support\Config;

final class SentinelServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('sentinel')
            ->hasConfigFile()
            // Read env-backed flags through the toolkit's Config helpers, never a bare truthiness
            // check: env() leaves `off`/`no` as non-empty (truthy) strings.
            ->contributesToAbout(static fn (): array => [
                'Enabled' => Config::boolean('sentinel.enabled', true) ? 'YES' : 'NO',
            ]);

        // Deliberately NO global facade alias (no extra.laravel.aliases, no hasFacadeAlias()):
        // cartalyst/sentinel registers the global `Sentinel` alias and ours would silently
        // replace it. Hosts import RoundlyConsulting\Sentinel\Facades\Sentinel.
    }

    public function register(): void
    {
        parent::register();

        // Container bindings (bind/singleton/scoped) go here — never in boot().
        $this->app->singleton(SentinelManager::class);
    }
}
