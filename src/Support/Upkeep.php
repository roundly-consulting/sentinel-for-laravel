<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\DatabaseManager;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Idempotency\Stores\DatabaseIdempotencyStore;
use RoundlyConsulting\Sentinel\Nonces\Stores\DatabaseNonceStore;
use Throwable;

/**
 * Sentinel's upkeep on the Laravel scheduler (`sentinel.schedule`), and whether a task skips
 * this run.
 *
 * A host that gets Sentinel only as another package's dependency never runs its migrations,
 * while the schedule is on by default: without this, its checkpoint, verify and prune would
 * fail on every run. A task skips while it works on Sentinel's tables and **none** of the
 * tables the configuration needs exists. One table present means the host uses Sentinel's
 * storage: every task runs exactly as before, and a half-migrated install fails as loudly as
 * before. Whatever it cannot rule out (an unreachable connection, an unreadable setting, a
 * store that cannot be built) it runs, so the task reports the failure itself. `sentinel:check`
 * fails while a task skips, so the silence never hides a host that forgot to migrate.
 *
 * Bound scoped: the tables are looked up once per scheduler run (one schema query per table
 * until the first is found), never remembered across processes, Octane requests or jobs.
 *
 * @internal
 */
final class Upkeep
{
    private ?bool $installed = null;

    public function __construct(
        private readonly Container $container,
        private readonly DatabaseManager $db,
    ) {}

    /**
     * The tasks the schedule registers, each with its scheduler frequency method: checkpoint
     * (with the ledger on), verify and prune — none while `sentinel.schedule.enabled` is off.
     *
     * @return array<string, string>
     */
    public static function tasks(): array
    {
        if (! Settings::scheduleEnabled()) {
            return [];
        }

        $tasks = [];

        foreach (['checkpoint', 'verify', 'prune'] as $task) {
            $frequency = Settings::scheduleFrequency($task);

            if ($frequency !== null && ($task !== 'checkpoint' || Settings::ledgerEnabled())) {
                $tasks[$task] = $frequency;
            }
        }

        return $tasks;
    }

    /**
     * Whether the scheduled task skips this run: it works on Sentinel's tables and the host
     * has none of them.
     */
    public function skips(string $task): bool
    {
        try {
            return $this->worksOnTables($task) && ! $this->installed();
        } catch (Throwable) {
            // Cannot tell: the task runs, and reports, as it always has.
            return false;
        }
    }

    /**
     * The scheduled tasks that skip this run.
     *
     * @return list<string>
     */
    public function skipped(): array
    {
        return array_values(array_filter(array_keys(self::tasks()), $this->skips(...)));
    }

    /**
     * Checkpoint and verify always read the seals and the ledger; prune only touches a table
     * while the store it prunes is Sentinel's database store — a cache store or one the host
     * bound is pruned whatever tables exist. The stores are whatever the container holds
     * now (config or a host binding), never what they would be by default.
     */
    private function worksOnTables(string $task): bool
    {
        return $task !== 'prune'
            || $this->container->get(IdempotencyStore::class) instanceof DatabaseIdempotencyStore
            || $this->container->get(NonceStore::class) instanceof DatabaseNonceStore;
    }

    private function installed(): bool
    {
        return $this->installed ??= $this->lookUp();
    }

    private function lookUp(): bool
    {
        foreach (StorageTable::needed() as $needed) {
            try {
                if ($this->db->connection($needed->connection)->getSchemaBuilder()->hasTable($needed->table)) {
                    return true;
                }
            } catch (Throwable) {
                // A connection that fails cannot say the tables are missing.
                return true;
            }
        }

        return false;
    }
}
