<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Commands;

use Illuminate\Console\Command;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * Delete expired idempotency keys and nonces (both unless one is named). Schedule it daily.
 * The ledger is never pruned.
 */
final class PruneCommand extends Command
{
    protected $signature = 'sentinel:prune
        {--idempotency : Only expired idempotency keys}
        {--nonces : Only expired nonces}
        {--dry-run : Count, delete nothing}';

    protected $description = 'Delete expired Sentinel idempotency keys and nonces';

    public function handle(SentinelManager $sentinel): int
    {
        $idempotency = (bool) $this->option('idempotency');
        $nonces = (bool) $this->option('nonces');
        $both = ! $idempotency && ! $nonces;
        $dryRun = (bool) $this->option('dry-run');

        try {
            $result = $sentinel->prune(new PruneOptions($both || $idempotency, $both || $nonces, $dryRun));
        } catch (SentinelException $exception) {
            $this->components->error($exception->getMessage());

            return self::FAILURE;
        }

        $verb = $dryRun ? 'Would delete' : 'Deleted';
        $this->components->twoColumnDetail("{$verb} idempotency keys", (string) $result->idempotencyKeys);
        $this->components->twoColumnDetail("{$verb} nonces", (string) $result->nonces);

        return self::SUCCESS;
    }
}
