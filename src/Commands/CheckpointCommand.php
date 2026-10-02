<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Console\Isolatable;
use RoundlyConsulting\Sentinel\Commands\Concerns\ReadsOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPublication;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Support\Tables;

/**
 * Fold pending ledger entries into checkpoints, batch after batch until none is pending, and
 * publish them to the anchors. Schedule it every minute; one run per connection at a time
 * (a cache lock, on top of Isolatable).
 */
final class CheckpointCommand extends Command implements Isolatable
{
    use ReadsOptions;

    protected $signature = 'sentinel:checkpoint
        {--connection=* : Connections to checkpoint (default: sentinel.ledger.connections)}
        {--batch= : Ledger entries per checkpoint (default: sentinel.ledger.batch_size)}';

    protected $description = 'Checkpoint the Sentinel ledger and publish to the anchors';

    public function handle(SentinelManager $sentinel): int
    {
        try {
            $batch = $this->intOption('batch', 1, 100000);
            $connections = $this->connections();
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::INVALID;
        }

        $status = self::SUCCESS;

        foreach ($connections as $connection) {
            $name = Tables::connectionName($connection);
            $store = $this->laravel->make('cache')->store()->getStore();
            $run = fn (): int => $this->checkpoint($sentinel, $connection, $name, $batch);

            $result = $store instanceof LockProvider ? $store->lock("sentinel:checkpoint:{$name}", 600)->get($run) : $run();

            if ($result === false) {
                $this->components->warn("Another checkpoint run holds [{$name}]; skipped.");
            } elseif ($result !== self::SUCCESS) {
                $status = self::FAILURE;
            }
        }

        return $status;
    }

    private function checkpoint(SentinelManager $sentinel, ?string $connection, string $name, ?int $batch): int
    {
        $made = 0;

        try {
            while (($result = $sentinel->checkpoint(new CheckpointOptions($connection, $batch))) !== null) {
                $made++;
                $anchors = array_map(static fn (AnchorPublication $publication): string => $publication->anchor.($publication->published ? ' ✓' : ' ✗'), $result->anchors);

                $this->components->twoColumnDetail(
                    "[{$name}] checkpoint #{$result->seq}",
                    "{$result->entries} entries".($anchors === [] ? '' : ' · anchors: '.implode(', ', $anchors)),
                );
            }
        } catch (SentinelException $exception) {
            $this->components->error("[{$name}] ".$exception->getMessage());

            return self::FAILURE;
        }

        if ($made === 0) {
            $this->components->info("[{$name}] nothing to checkpoint.");
        }

        return self::SUCCESS;
    }

    /**
     * @return list<string|null>
     */
    private function connections(): array
    {
        $given = array_values(array_filter($this->option('connection'), static fn (?string $name): bool => $name !== null && $name !== ''));

        return $given !== [] ? $given : Settings::ledgerConnections();
    }
}
