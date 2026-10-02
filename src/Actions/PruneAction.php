<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions;

use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneResult;
use RoundlyConsulting\Sentinel\Idempotency\Stores\DatabaseIdempotencyStore;
use RoundlyConsulting\Sentinel\Nonces\Stores\DatabaseNonceStore;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Delete expired idempotency keys and nonces (`sentinel:prune`). Cache stores expire on their
 * own and report 0; a dry run counts what the database stores would delete. The ledger is
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
            $this->idempotency instanceof DatabaseIdempotencyStore => $this->idempotency->countExpired($now),
            default => 0,
        };

        $nonces = ! $options->nonces ? 0 : match (true) {
            ! $options->dryRun => $this->nonces->prune($now),
            $this->nonces instanceof DatabaseNonceStore => $this->nonces->countExpired($now),
            default => 0,
        };

        return new PruneResult($keys, $nonces);
    }
}
