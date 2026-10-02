<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;

final class SentinelServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('sentinel')
            ->hasConfigFile()
            // Presence and flags only — never key material, never a database key's kid.
            ->contributesToAbout(static fn (): array => [
                // Disambiguates from Laravel\Sentinel\SentinelManager (laravel/sentinel).
                'Manager' => SentinelManager::class,
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
