<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions;

use Closure;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use ReflectionClass;
use ReflectionMethod;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\HealthCheck;
use RoundlyConsulting\Sentinel\DataTransferObjects\HealthReport;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Inspector;
use RoundlyConsulting\Sentinel\Enums\HealthStatus;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSealDefinitionException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\ModelDiscovery;
use RoundlyConsulting\Sentinel\Support\SealUsage;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;
use Throwable;

/**
 * The installation health check behind `Sentinel::check()` and `sentinel:check`: every
 * misconfiguration that silently weakens the guarantees, reported in one place and in a
 * stable order — configuration, signing keys, `APP_KEY`, tables, models, anchors, checkpoint
 * backlog, scheduling, seals on retired keys, stores. Read-only. Messages name rings, tables
 * and classes — never key material and never a key id.
 */
final readonly class CheckInstallationAction
{
    private const array TASKS = ['checkpoint', 'verify', 'prune'];

    public function __construct(
        private Container $container,
        private KeyStoreManager $keys,
        private AnchorManager $anchors,
        private DefinitionRegistry $registry,
        private Inspector $inspector,
    ) {}

    public function execute(): HealthReport
    {
        $checks = [
            'configuration' => $this->configuration(...),
            'signing_keys' => $this->signingKeys(...),
            'app_key' => $this->appKey(...),
            'tables' => $this->tables(...),
            'models' => $this->models(...),
            'anchors' => $this->anchorsReachable(...),
            'checkpoints' => $this->checkpoints(...),
            'schedule' => $this->schedule(...),
            'retired_keys' => $this->retiredKeys(...),
            'stores' => $this->stores(...),
        ];

        $report = [];

        foreach ($checks as $name => $check) {
            $report[] = $this->run($name, $check);
        }

        return new HealthReport($report);
    }

    /**
     * @param  Closure(): array{0: HealthStatus, 1: string}  $check
     */
    private function run(string $name, Closure $check): HealthCheck
    {
        try {
            [$status, $message] = $check();
        } catch (Throwable $exception) {
            [$status, $message] = [HealthStatus::Failure, 'could not be checked: '.self::describe($exception)];
        }

        return new HealthCheck($name, $status, $message);
    }

    /**
     * Every reader of config/sentinel.php, and every signature profile.
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function configuration(): array
    {
        $problems = [];
        $read = static function (Closure $reader) use (&$problems): void {
            try {
                $reader();
            } catch (InvalidSentinelConfigurationException|SealingMisconfiguredException $exception) {
                $problems[$exception->getMessage()] = true;
            }
        };

        foreach ((new ReflectionClass(Settings::class))->getMethods(ReflectionMethod::IS_PUBLIC | ReflectionMethod::IS_STATIC) as $method) {
            if ($method->getNumberOfRequiredParameters() === 0) {
                $read(static fn (): mixed => $method->invoke(null));
            }
        }

        $read(static function (): void {
            foreach (Settings::rings() as $ring) {
                Settings::ring($ring);
            }
        });
        $read(static function (): void {
            foreach (Settings::anchors() as $anchor) {
                Settings::anchorDriver($anchor);
            }
        });

        foreach (self::TASKS as $task) {
            $read(static fn (): ?string => Settings::scheduleFrequency($task));
        }

        $profiles = config('sentinel.signatures.profiles');

        foreach (is_array($profiles) ? array_keys($profiles) : [] as $profile) {
            $read(static fn (): mixed => ProfileResolver::resolve((string) $profile));
        }

        $read(static fn (): mixed => ProfileResolver::resolve());

        return $problems === []
            ? [HealthStatus::Ok, 'config/sentinel.php is valid']
            : [HealthStatus::Failure, implode(' ', array_keys($problems))];
    }

    /**
     * The default ring, the ledger ring and every ring a sealable model's seal uses must be
     * able to sign — unless this node does not seal (`sealing.auto` off: verify-only).
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function signingKeys(): array
    {
        $rings = [Settings::defaultRing()];

        if (Settings::ledgerEnabled()) {
            $rings[] = Settings::ledgerRing();
        }

        foreach ($this->sealables() as $class) {
            try {
                foreach ($this->registry->for($class)->all() as $seal) {
                    $rings[] = $seal->ring;
                }
            } catch (InvalidSealDefinitionException|SealingMisconfiguredException) {
                // Reported by the models check.
            }
        }

        $missing = [];
        $broken = [];

        foreach (array_values(array_unique($rings)) as $ring) {
            try {
                $this->keys->signingKey($ring);
            } catch (NoSigningKeyException) {
                $missing[] = $ring;
            } catch (Throwable $exception) {
                $broken[] = "ring [{$ring}]: ".self::describe($exception);
            }
        }

        if ($broken !== []) {
            return [HealthStatus::Failure, implode(' ', $broken)];
        }

        if ($missing === []) {
            return [HealthStatus::Ok, 'every ring that seals has a signing key: '.implode(', ', array_values(array_unique($rings)))];
        }

        $message = 'no active signing key in ring(s) '.implode(', ', $missing).' — generate one with `php artisan sentinel:key:generate --ring=<ring>`';

        return Settings::autoSeal()
            ? [HealthStatus::Failure, $message]
            : [HealthStatus::Warning, $message.' (sealing.auto is off: a verify-only node)'];
    }

    /**
     * Database keys and encrypted idempotency responses are encrypted with APP_KEY.
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function appKey(): array
    {
        $users = array_values(array_filter(Settings::rings(), self::usesDatabase(...)));

        if (Settings::idempotencyEncrypt()) {
            $users[] = 'idempotency.encrypt';
        }

        $key = config('app.key');

        if ($users === [] || (is_string($key) && $key !== '')) {
            return [HealthStatus::Ok, $users === [] ? 'not needed' : 'set'];
        }

        return [HealthStatus::Failure, 'app.key is empty, but '.implode(', ', $users).' encrypt with it — set APP_KEY'];
    }

    /**
     * Every table the configuration needs exists on its connection.
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function tables(): array
    {
        $needed = [];
        $keyConnection = Settings::keyConnection();

        if (array_filter(Settings::rings(), self::usesDatabase(...)) !== []) {
            $needed[] = [$keyConnection, 'sentinel_keys'];
        }

        if (Settings::idempotencyStore() === 'database') {
            $needed[] = [$keyConnection, 'sentinel_idempotency_keys'];
        }

        if (Settings::nonceStore() === 'database') {
            $needed[] = [$keyConnection, 'sentinel_nonces'];
        }

        foreach (Settings::ledgerConnections() as $connection) {
            $needed[] = [$connection, 'sentinel_seals'];

            if (Settings::ledgerEnabled()) {
                $needed[] = [$connection, 'sentinel_ledger'];
                $needed[] = [$connection, 'sentinel_checkpoints'];
            }
        }

        $missing = [];

        foreach ($needed as [$connection, $table]) {
            $name = Tables::connectionName($connection);

            try {
                $exists = $this->container->make('db')->connection($connection)->getSchemaBuilder()->hasTable($table);
            } catch (Throwable $exception) {
                $missing[] = "{$table} on [{$name}] (connection failed: ".class_basename($exception).')';

                continue;
            }

            if (! $exists) {
                $missing[] = "{$table} on [{$name}]";
            }
        }

        return $missing === []
            ? [HealthStatus::Ok, count($needed).' tables present']
            : [HealthStatus::Failure, 'missing: '.implode(', ', $missing).' — publish and run the migrations (php artisan vendor:publish --tag=sentinel-migrations)'];
    }

    /**
     * Every sealable model compiles and its table has every sealed column.
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function models(): array
    {
        $discovery = ModelDiscovery::run();
        $problems = [];

        foreach ($discovery->models as $class) {
            try {
                $seals = $this->registry->for($class)->all();
                $missing = [];

                foreach ($seals as $seal) {
                    array_push($missing, ...$this->inspector->missingColumns(new $class, $seal));
                }

                if ($missing !== []) {
                    $problems[] = "[{$class}] seals columns its table lacks: ".implode(', ', array_values(array_unique($missing)));
                }
            } catch (InvalidSealDefinitionException|SealingMisconfiguredException|InvalidSentinelConfigurationException $exception) {
                $problems[] = $exception->getMessage();
            }
        }

        if ($problems !== []) {
            return [HealthStatus::Failure, implode(' ', $problems)];
        }

        if ($discovery->models === []) {
            return [HealthStatus::Warning, 'no sealable models: list them in sentinel.models, or seal rows first'];
        }

        $summary = sprintf('%d configured, %d discovered', $discovery->configured, count($discovery->models) - $discovery->configured);

        return $discovery->unresolved === []
            ? [HealthStatus::Ok, $summary]
            : [HealthStatus::Warning, $summary.'; seals of '.count($discovery->unresolved).' stored type(s) no longer resolve to a sealable model (check the morph map)'];
    }

    /**
     * Without an anchor, a restore of the whole database to an older snapshot is undetectable.
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function anchorsReachable(): array
    {
        $names = Settings::anchors();

        if ($names === []) {
            return [HealthStatus::Warning, 'none configured: a rollback of the whole database is undetectable (set SENTINEL_ANCHORS)'];
        }

        $unreachable = [];

        foreach ($names as $name) {
            try {
                $anchor = $this->anchors->build($name);

                foreach (Settings::ledgerConnections() as $connection) {
                    $anchor->latest(Tables::connectionName($connection));
                }
            } catch (InvalidSentinelConfigurationException $exception) {
                throw $exception;
            } catch (Throwable $exception) {
                $unreachable[] = "[{$name}] (".class_basename($exception).')';
            }
        }

        if ($unreachable !== []) {
            return [HealthStatus::Failure, 'unreachable: '.implode(', ', $unreachable)];
        }

        return in_array('cache', $names, true) ? self::cacheAnchorPlacement() ?? [HealthStatus::Ok, implode(', ', $names)] : [HealthStatus::Ok, implode(', ', $names)];
    }

    /**
     * An anchor is worth something only outside what it protects: a store in process memory
     * starts empty in every process, and one in a ledger database goes with the checkpoints
     * an attacker truncates or a restore rolls back.
     *
     * @return array{0: HealthStatus, 1: string}|null
     */
    private static function cacheAnchorPlacement(): ?array
    {
        $configured = config('sentinel.ledger.anchor_drivers.cache.store');
        $store = is_string($configured) && $configured !== '' ? $configured : config('cache.default');
        $driver = is_string($store) ? config("cache.stores.{$store}.driver") : null;
        $ledger = array_map(Tables::connectionName(...), Settings::ledgerConnections());
        $connection = config("cache.stores.{$store}.connection") ?? config('database.default');

        return match (true) {
            in_array($driver, ['array', 'null'], true) => [HealthStatus::Failure, "[cache] uses the [{$store}] store, which lives in process memory: every process starts without the anchor"],
            $driver === 'database' && in_array($connection, $ledger, true) => [HealthStatus::Failure, "[cache] uses the [{$store}] store in the database it protects: a restore or an attacker removes the anchor with the checkpoints"],
            ! is_string($configured) || $configured === '' => [HealthStatus::Warning, "[cache] uses the default cache store [{$store}]: set SENTINEL_ANCHOR_CACHE_STORE to a store outside the protected database"],
            default => null,
        };
    }

    /**
     * Ledger entries older than `ledger.backlog_warning_seconds` that no checkpoint has
     * claimed: the scheduled `sentinel:checkpoint` is not running.
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function checkpoints(): array
    {
        if (! Settings::ledgerEnabled()) {
            return [HealthStatus::Ok, 'the ledger is off'];
        }

        $seconds = Settings::backlogWarningSeconds();
        $threshold = Clock::database(Clock::now()->subSeconds($seconds));
        $stale = 0;

        foreach (Settings::ledgerConnections() as $connection) {
            $stale += Tables::ledgerOn($connection)->whereNull('checkpoint_id')->where('occurred_at', '<', $threshold)->count();
        }

        return $stale === 0
            ? [HealthStatus::Ok, 'no backlog']
            : [HealthStatus::Warning, "{$stale} ledger entries are older than {$seconds}s and not checkpointed — is sentinel:checkpoint scheduled?"];
    }

    /**
     * @return array{0: HealthStatus, 1: string}
     */
    private function schedule(): array
    {
        if (Settings::scheduleEnabled()) {
            return [HealthStatus::Ok, 'auto (sentinel.schedule)'];
        }

        if (! Settings::ledgerEnabled()) {
            return [HealthStatus::Ok, 'manual; the ledger is off'];
        }

        foreach ($this->container->make(Schedule::class)->events() as $event) {
            if (str_contains((string) $event->command, 'sentinel:checkpoint')) {
                return [HealthStatus::Ok, 'manual'];
            }
        }

        return [HealthStatus::Warning, 'sentinel.schedule.enabled is off and no sentinel:checkpoint is scheduled: the rollback window grows until it is'];
    }

    /**
     * Seals still made with a revoked, retired or unknown key: re-seal them with
     * `sentinel:reseal --from-key=` (`sentinel:key:list` shows which keys seal what).
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function retiredKeys(): array
    {
        $counts = [];

        foreach (SealUsage::perKey() as $usage) {
            $state = $this->keyState($usage->ring, $usage->keyId);

            if ($state !== null) {
                $label = "{$state} keys in ring [".(preg_match('/^[a-z0-9_-]{1,64}$/D', $usage->ring) === 1 ? $usage->ring : '(invalid)').']';
                $counts[$label] = ($counts[$label] ?? 0) + $usage->seals;
            }
        }

        if ($counts === []) {
            return [HealthStatus::Ok, 'every seal uses a usable key'];
        }

        $parts = [];

        foreach ($counts as $label => $count) {
            $parts[] = "{$count} seal(s) on {$label}";
        }

        return [HealthStatus::Warning, implode(', ', $parts).' — re-seal them with `php artisan sentinel:reseal --from-key=<kid>` (sentinel:key:list shows the keys)'];
    }

    private function keyState(string $ring, string $keyId): ?string
    {
        if (! in_array($ring, Settings::rings(), true)) {
            return 'unknown';
        }

        $key = $this->keys->lookup($ring, $keyId)->key;

        return match (true) {
            $key === null => 'unknown',
            $key->status === KeyStatus::Revoked => 'revoked',
            $key->status === KeyStatus::Retired => 'retired',
            default => null,
        };
    }

    /**
     * The idempotency and nonce stores can be built (a cache store must support locks).
     *
     * @return array{0: HealthStatus, 1: string}
     */
    private function stores(): array
    {
        $problems = [];

        foreach (['idempotency' => IdempotencyStore::class, 'nonce' => NonceStore::class] as $label => $contract) {
            try {
                $this->container->make($contract);
            } catch (Throwable $exception) {
                $problems[] = "the {$label} store cannot be built: ".self::describe($exception);
            }
        }

        return $problems === []
            ? [HealthStatus::Ok, Settings::idempotencyStore().' (idempotency), '.Settings::nonceStore().' (nonces)']
            : [HealthStatus::Failure, implode(' ', $problems)];
    }

    /**
     * @return list<class-string<Model>>
     */
    private function sealables(): array
    {
        try {
            return ModelDiscovery::run()->models;
        } catch (Throwable) {
            // No tables yet (reported by the tables check): the configured models only.
            return Settings::models();
        }
    }

    private static function usesDatabase(string $ring): bool
    {
        $config = Settings::ring($ring);

        return $config->driver === 'database' || ($config->driver === 'chain' && in_array('database', $config->drivers, true));
    }

    /**
     * A safe description of a failure: configuration messages name settings only; anything
     * else is reduced to its class (a key-material or key-store message can carry a key id).
     */
    private static function describe(Throwable $exception): string
    {
        return $exception instanceof InvalidSentinelConfigurationException || $exception instanceof SealingMisconfiguredException
            ? $exception->getMessage()
            : class_basename($exception);
    }
}
