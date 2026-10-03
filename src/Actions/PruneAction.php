<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneResult;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\CountsExpired;

/**
 * Delete expired idempotency keys and nonces (`sentinel:prune`). Cache stores expire on their
 * own and report 0; a dry run counts what a store that can preview it (the database stores,
 * the fake's in-memory ones) would delete. The ledger is
 * never pruned.
 */
final readonly class PruneAction
{
    public function __construct(
        private IdempotencyStore $idempotency,
        private NonceStore $nonces,
    ) {}

    public function execute(PruneOptions $options): PruneResult
    {
        $now = Clock::now();

        $keys = ! $options->idempotency ? 0 : match (true) {
            ! $options->dryRun => $this->idempotency->prune($now),
            $this->idempotency instanceof CountsExpired => $this->idempotency->countExpired($now),
            default => 0,
        };

        $nonces = ! $options->nonces ? 0 : match (true) {
            ! $options->dryRun => $this->nonces->prune($now),
            $this->nonces instanceof CountsExpired => $this->nonces->countExpired($now),
            default => 0,
        };

        return new PruneResult($keys, $nonces);
    }
}
