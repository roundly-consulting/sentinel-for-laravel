<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * What `Sentinel::verifyLedger()` checks. A null connection verifies every connection in
 * `sentinel.ledger.connections`; `manualAnchor` compares a payload copied out of a
 * write-only anchor (a log line) as well.
 */
final readonly class LedgerVerifyOptions
{
    public function __construct(
        public ?string $connection = null,
        public bool $entities = true,
        public int $chunk = 1000,
        public ?AnchorPayload $manualAnchor = null,
    ) {}
}
