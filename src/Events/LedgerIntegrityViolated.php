<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;

/**
 * Ledger verification found integrity violations on a connection (dispatched synchronously).
 * Identifiers and short details only, never values.
 */
final readonly class LedgerIntegrityViolated
{
    /**
     * @param  list<LedgerFinding>  $findings
     */
    public function __construct(
        public string $connection,
        public array $findings,
    ) {}
}
