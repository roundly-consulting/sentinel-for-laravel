<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use RoundlyConsulting\PackageToolkit\Concerns\RegistersBlueprintMacros;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\Sentinel\Commands\KeyGenerateCommand;
use RoundlyConsulting\Sentinel\Commands\KeyListCommand;
use RoundlyConsulting\Sentinel\Commands\KeyRetireCommand;
use RoundlyConsulting\Sentinel\Commands\KeyRevokeCommand;
use RoundlyConsulting\Sentinel\Commands\KeyRotateCommand;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Keys\KeyCache;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Settings;

final class SentinelServiceProvider extends PackageServiceProvider
{
    use RegistersBlueprintMacros;

    public function configurePackage(Package $package): void
    {
        $package
            ->name('sentinel')
            ->hasConfigFile()
            // Publish-only: the host publishes them timestamped (never auto-loaded).
            ->hasMigrations()
            ->hasCommands([
                KeyGenerateCommand::class,
                KeyRotateCommand::class,
                KeyRevokeCommand::class,
                KeyRetireCommand::class,
                KeyListCommand::class,
            ])
            // Presence and flags only — never key material, never a database key's kid.
            ->contributesToAbout(static fn (): array => self::about());

        // Deliberately NO global facade alias (no extra.laravel.aliases, no hasFacadeAlias()):
        // cartalyst/sentinel registers the global `Sentinel` alias and ours would silently
        // replace it. Hosts import RoundlyConsulting\Sentinel\Facades\Sentinel.
    }

    public function register(): void
    {
        parent::register();

        $this->app->singleton(SentinelManager::class);
        // Driver factories only (code, never key material).
        $this->app->singleton(KeyStoreManager::class);
        // Loaded stores and decrypted keys: one request / one job, then gone (Octane-safe).
        $this->app->scoped(KeyCache::class);
    }

    public function boot(): void
    {
        parent::boot();

        // morphKey() must exist before the host runs the published migrations.
        $this->registerBlueprintMacros();
    }

    /**
     * @return array<string, string>
     */
    private static function about(): array
    {
        try {
            $ring = Settings::defaultRing();
            $rows = [
                'Default ring / driver' => sprintf('%s (%s)', $ring, Settings::ring($ring)->driver),
                'Rings' => implode(', ', Settings::rings()),
            ];
        } catch (SentinelException) {
            $rows = ['Default ring / driver' => 'invalid configuration'];
        }

        // Disambiguates from Laravel\Sentinel\SentinelManager (laravel/sentinel).
        return [...$rows, 'Manager' => SentinelManager::class];
    }
}
