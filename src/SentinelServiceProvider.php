<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\Container;
use Illuminate\Log\LogManager;
use RoundlyConsulting\PackageToolkit\Concerns\RegistersBlueprintMacros;
use RoundlyConsulting\PackageToolkit\Package;
use RoundlyConsulting\PackageToolkit\PackageServiceProvider;
use RoundlyConsulting\Sentinel\Canonical\FieldTagger;
use RoundlyConsulting\Sentinel\Commands\CheckCommand;
use RoundlyConsulting\Sentinel\Commands\CheckpointCommand;
use RoundlyConsulting\Sentinel\Commands\InspectCommand;
use RoundlyConsulting\Sentinel\Commands\InstallCommand;
use RoundlyConsulting\Sentinel\Commands\KeyGenerateCommand;
use RoundlyConsulting\Sentinel\Commands\KeyImportCommand;
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
use RoundlyConsulting\Sentinel\Engine\DocumentBuilder;
use RoundlyConsulting\Sentinel\Engine\LedgerWriter;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\SchemaColumns;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Http\ClientMacros;
use RoundlyConsulting\Sentinel\Http\CollectionMacros;
use RoundlyConsulting\Sentinel\Http\Middleware\ConsumeSingleUseUrl;
use RoundlyConsulting\Sentinel\Http\Middleware\EnsureIdempotency;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifyHttpSignature;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifySeals;
use RoundlyConsulting\Sentinel\Idempotency\RequestScope;
use RoundlyConsulting\Sentinel\Idempotency\ResponseVault;
use RoundlyConsulting\Sentinel\Idempotency\Stores\CacheIdempotencyStore;
use RoundlyConsulting\Sentinel\Idempotency\Stores\DatabaseIdempotencyStore;
use RoundlyConsulting\Sentinel\Keys\KeyCache;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
use RoundlyConsulting\Sentinel\Nonces\Stores\CacheNonceStore;
use RoundlyConsulting\Sentinel\Nonces\Stores\DatabaseNonceStore;
use RoundlyConsulting\Sentinel\Support\GateAcknowledgementPolicy;
use RoundlyConsulting\Sentinel\Support\ModelDiscovery;
use RoundlyConsulting\Sentinel\Support\SealingScope;
use RoundlyConsulting\Sentinel\Support\Settings;
use Throwable;

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
                CheckCommand::class,
                InstallCommand::class,
                VerifyCommand::class,
                CheckpointCommand::class,
                ResealCommand::class,
                SealMissingCommand::class,
                InspectCommand::class,
                PruneCommand::class,
                KeyGenerateCommand::class,
                KeyImportCommand::class,
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
        // Table column listings: one schema query per table per request / job, then gone.
        $this->app->scoped(SchemaColumns::class);

        // Stateless engine services (final readonly, no key material of their own): built
        // once per request / job instead of once per verified row, and flushed with the
        // scope — never process-wide, so an Octane worker cannot carry one into the next.
        foreach ([Verifier::class, Sealer::class, DocumentBuilder::class, LedgerWriter::class, ReadBack::class, FieldTagger::class, Signers::class] as $service) {
            $this->app->scoped($service);
        }
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
        $router->aliasMiddleware('sentinel.signed', VerifyHttpSignature::class);
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

        $this->callAfterResolving(Schedule::class, static function (Schedule $schedule): void {
            self::schedule($schedule);
        });
    }

    /**
     * The upkeep tasks (`sentinel.schedule`): checkpoint (with the ledger on), a full verify
     * that tolerates an empty install, prune — each without overlapping, on one server.
     */
    private static function schedule(Schedule $schedule): void
    {
        if (! Settings::scheduleEnabled()) {
            return;
        }

        $ledger = Settings::ledgerEnabled();
        $tasks = [
            'checkpoint' => $ledger ? ['sentinel:checkpoint', [], 'Sentinel: checkpoint and anchor the ledger'] : null,
            'verify' => ['sentinel:verify', $ledger ? ['--allow-empty', '--ledger'] : ['--allow-empty'], 'Sentinel: verify every sealed model'],
            'prune' => ['sentinel:prune', [], 'Sentinel: prune expired idempotency keys and nonces'],
        ];

        foreach ($tasks as $task => $command) {
            $frequency = Settings::scheduleFrequency($task);

            if ($frequency === null || $command === null) {
                continue;
            }

            [$name, $parameters, $description] = $command;
            $schedule->command($name, $parameters)->{$frequency}()->withoutOverlapping()->onOneServer()->description($description);
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
     * Presence only — never the key id or material.
     */
    private static function signingKey(string $ring): string
    {
        try {
            app(KeyStoreManager::class)->signingKey($ring);

            return 'present';
        } catch (NoSigningKeyException) {
            return 'missing';
        } catch (Throwable) {
            return 'unusable';
        }
    }

    /**
     * "N configured, M discovered" — discovery reads the seal and ledger tables, so an
     * unreachable or unmigrated database is reported, never fatal.
     */
    private static function sealableModels(): string
    {
        $configured = count(Settings::models());

        try {
            $discovery = ModelDiscovery::run();
        } catch (Throwable) {
            // `about` must never fail: no tables yet, an unreachable or unknown connection.
            return "{$configured} configured, discovery unavailable (database)";
        }

        return sprintf('%d configured, %d discovered', $discovery->configured, count($discovery->models) - $discovery->configured);
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
                'Signing key (default ring)' => self::signingKey($ring),
                'Rings' => implode(', ', Settings::rings()),
                'Auto-seal' => Settings::autoSeal() ? 'ON' : 'OFF',
                'Tampered writes' => Settings::onTamperedWrite()->value,
                'Ledger' => Settings::ledgerEnabled() ? 'ON' : 'OFF',
                'Anchors' => Settings::anchors() === [] ? 'none (whole-database rollback undetectable)' : implode(', ', Settings::anchors()),
                'Idempotency store' => Settings::idempotencyStore(),
                'Nonce store' => Settings::nonceStore(),
                'Signature profiles' => (string) count(is_array(config('sentinel.signatures.profiles')) ? config('sentinel.signatures.profiles') : []),
                'Sealable models' => self::sealableModels(),
                'Schedule' => Settings::scheduleEnabled() ? 'auto' : 'manual',
            ];
        } catch (SentinelException) {
            $rows = ['Default ring / driver' => 'invalid configuration'];
        }

        // Disambiguates from Laravel\Sentinel\SentinelManager (laravel/sentinel).
        return [...$rows, 'Manager' => SentinelManager::class];
    }
}
