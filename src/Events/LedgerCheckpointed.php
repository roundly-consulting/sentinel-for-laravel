<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use Illuminate\Contracts\Events\ShouldDispatchAfterCommit;

/**
 * A checkpoint was written (after commit).
 */
final readonly class LedgerCheckpointed implements ShouldDispatchAfterCommit
{
    public function __construct(
        public string $connection,
        public int $seq,
        public int $entries,
        public string $root,
    ) {}
}
