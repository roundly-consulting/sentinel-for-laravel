<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Illuminate\Contracts\Container\Container;
use Illuminate\Log\LogManager;
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
use RoundlyConsulting\Sentinel\Commands\PruneCommand;
use RoundlyConsulting\Sentinel\Commands\ResealCommand;
use RoundlyConsulting\Sentinel\Commands\SealMissingCommand;
use RoundlyConsulting\Sentinel\Commands\VerifyCommand;
use RoundlyConsulting\Sentinel\Contracts\AcknowledgementPolicy;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyScopeResolver;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Http\ClientMacros;
use RoundlyConsulting\Sentinel\Http\CollectionMacros;
use RoundlyConsulting\Sentinel\Http\Middleware\ConsumeSingleUseUrl;
use RoundlyConsulting\Sentinel\Http\Middleware\EnsureIdempotency;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifySeals;
use RoundlyConsulting\Sentinel\Idempotency\RequestScope;
use RoundlyConsulting\Sentinel\Idempotency\ResponseVault;
use RoundlyConsulting\Sentinel\Idempotency\Stores\CacheIdempotencyStore;
use RoundlyConsulting\Sentinel\Idempotency\Stores\DatabaseIdempotencyStore;
use RoundlyConsulting\Sentinel\Keys\KeyCache;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
use RoundlyConsulting\Sentinel\Nonces\Stores\CacheNonceStore;
use RoundlyConsulting\Sentinel\Nonces\Stores\DatabaseNonceStore;
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
                PruneCommand::class,
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
        $this->app->bindIf(IdempotencyScopeResolver::class, RequestScope::class);
        // From config; a host binding of the contract replaces them.
        $this->app->bind(IdempotencyStore::class, static fn (Container $app): IdempotencyStore => self::idempotencyStore($app));
        $this->app->bind(NonceStore::class, static fn (Container $app): NonceStore => self::nonceStore($app));
    }

    public function boot(): void
    {
        parent::boot();

        // morphKey() must exist before the host runs the published migrations.
        $this->registerBlueprintMacros();

        $router = $this->app->make('router');
        $router->aliasMiddleware('sentinel.verified', VerifySeals::class);
        $router->aliasMiddleware('sentinel.idempotent', EnsureIdempotency::class);
        $router->aliasMiddleware('sentinel.single-use', ConsumeSingleUseUrl::class);

        CollectionMacros::register();
        ClientMacros::register();

        // A cache store without atomic locks would break the guarantees: refuse it up front.
        if (Settings::idempotencyStore() === 'cache') {
            $this->app->make(IdempotencyStore::class);
        }

        if (Settings::nonceStore() === 'cache') {
            $this->app->make(NonceStore::class);
        }
    }

    private static function idempotencyStore(Container $app): IdempotencyStore
    {
        return match (Settings::idempotencyStore()) {
            'database' => $app->make(DatabaseIdempotencyStore::class),
            'cache' => new CacheIdempotencyStore($app->make('cache')->store(Settings::idempotencyCacheStore()), $app->make(ResponseVault::class), $app->make(LogManager::class)),
            default => throw InvalidSentinelConfigurationException::invalidValue('idempotency.store', 'must be database or cache — or bind RoundlyConsulting\\Sentinel\\Contracts\\IdempotencyStore yourself'),
        };
    }

    private static function nonceStore(Container $app): NonceStore
    {
        return match (Settings::nonceStore()) {
            'database' => new DatabaseNonceStore,
            'cache' => new CacheNonceStore($app->make('cache')->store(Settings::nonceCacheStore())),
            default => throw InvalidSentinelConfigurationException::invalidValue('nonces.store', 'must be database or cache — or bind RoundlyConsulting\\Sentinel\\Contracts\\NonceStore yourself'),
        };
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
                'Idempotency store' => Settings::idempotencyStore(),
                'Nonce store' => Settings::nonceStore(),
                'Registered models' => (string) count(Settings::models()),
            ];
        } catch (SentinelException) {
            $rows = ['Default ring / driver' => 'invalid configuration'];
        }

        // Disambiguates from Laravel\Sentinel\SentinelManager (laravel/sentinel).
        return [...$rows, 'Manager' => SentinelManager::class];
    }
}
