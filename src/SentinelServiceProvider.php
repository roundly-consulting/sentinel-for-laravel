<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use RoundlyConsulting\PackageToolkit\Concerns\RegistersBlueprintMacros;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\Sentinel\Commands\CheckpointCommand;
use RoundlyConsulting\Sentinel\Commands\InspectCommand;
use RoundlyConsulting\Sentinel\Commands\KeyGenerateCommand;
use RoundlyConsulting\Sentinel\Commands\KeyListCommand;
use RoundlyConsulting\Sentinel\Commands\KeyRetireCommand;
use RoundlyConsulting\Sentinel\Commands\KeyRevokeCommand;
use RoundlyConsulting\Sentinel\Commands\KeyRotateCommand;
use RoundlyConsulting\Sentinel\Commands\ResealCommand;
use RoundlyConsulting\Sentinel\Commands\SealMissingCommand;
use RoundlyConsulting\Sentinel\Commands\VerifyCommand;
use RoundlyConsulting\Sentinel\Contracts\AcknowledgementPolicy;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Http\CollectionMacros;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifySeals;
use RoundlyConsulting\Sentinel\Keys\KeyCache;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
use RoundlyConsulting\Sentinel\Support\GateAcknowledgementPolicy;
use RoundlyConsulting\Sentinel\Support\SealingScope;
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
            ->hasTranslations()
            ->hasCommands([
                VerifyCommand::class,
                CheckpointCommand::class,
                ResealCommand::class,
                SealMissingCommand::class,
                InspectCommand::class,
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
        // Compiled seal definitions derive from code only — safe across Octane requests.
        $this->app->singleton(DefinitionRegistry::class);
        // Driver factories only (code, never key material).
        $this->app->singleton(KeyStoreManager::class);
        $this->app->singleton(AnchorManager::class);
        // Loaded stores and decrypted keys: one request / one job, then gone (Octane-safe).
        $this->app->scoped(KeyCache::class);
        // Suspension flags: never outlive the request or job that set them.
        $this->app->scoped(SealingScope::class);
        // Host-rebindable (e.g. an approval flow).
        $this->app->bindIf(AcknowledgementPolicy::class, GateAcknowledgementPolicy::class);
    }

    public function boot(): void
    {
        parent::boot();

        // morphKey() must exist before the host runs the published migrations.
        $this->registerBlueprintMacros();

        $this->app->make('router')->aliasMiddleware('sentinel.verified', VerifySeals::class);

        CollectionMacros::register();
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
                'Auto-seal' => Settings::autoSeal() ? 'ON' : 'OFF',
                'Tampered writes' => Settings::onTamperedWrite()->value,
                'Ledger' => Settings::ledgerEnabled() ? 'ON' : 'OFF',
                'Anchors' => Settings::anchors() === [] ? 'none (whole-database rollback undetectable)' : implode(', ', Settings::anchors()),
                'Registered models' => (string) count(Settings::models()),
            ];
        } catch (SentinelException) {
            $rows = ['Default ring / driver' => 'invalid configuration'];
        }

        // Disambiguates from Laravel\Sentinel\SentinelManager (laravel/sentinel).
        return [...$rows, 'Manager' => SentinelManager::class];
    }
}
