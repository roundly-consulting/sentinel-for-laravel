<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;

/**
 * Ledger verification found integrity violations (`LedgerReport::throwIfViolated()`).
 */
final class LedgerIntegrityException extends SentinelException
{
    /**
     * @param  list<LedgerFinding>  $findings
     */
    private function __construct(string $message, private readonly array $findings)
    {
        parent::__construct($message);
    }

    /**
     * @param  list<LedgerFinding>  $findings
     */
    public static function withFindings(array $findings): self
    {
        $kinds = array_values(array_unique(array_map(static fn (LedgerFinding $finding): string => $finding->kind->value, $findings)));

        return new self(count($findings).' ledger integrity violation(s): '.implode(', ', $kinds).'.', $findings);
    }

    /**
     * @return list<LedgerFinding>
     */
    public function findings(): array
    {
        return $this->findings;
    }
}
