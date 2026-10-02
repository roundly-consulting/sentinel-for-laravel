<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * What `sentinel:prune` removes: expired idempotency keys and/or expired nonces.
 */
final readonly class PruneOptions
{
    public function __construct(
        public bool $idempotency = true,
        public bool $nonces = true,
        public bool $dryRun = false,
    ) {}
}
