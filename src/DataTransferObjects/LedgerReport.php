<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIntegrityException;

/**
 * The outcome of verifying the ledger: how much was checked and what was found.
 */
final readonly class LedgerReport
{
    /**
     * @param  list<LedgerFinding>  $findings
     */
    public function __construct(
        public int $checkpoints,
        public int $entries,
        public int $anchorsChecked,
        public array $findings,
    ) {}

    /**
     * No integrity violation (a backlog or an unreachable anchor is not one).
     */
    public function clean(): bool
    {
        return $this->violations() === [];
    }

    /**
     * @return list<LedgerFinding>
     */
    public function violations(): array
    {
        return array_values(array_filter($this->findings, static fn (LedgerFinding $finding): bool => $finding->isViolation()));
    }

    public function has(LedgerFindingKind ...$kinds): bool
    {
        foreach ($this->findings as $finding) {
            if (in_array($finding->kind, $kinds, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @throws LedgerIntegrityException when any violation was found
     */
    public function throwIfViolated(): void
    {
        $violations = $this->violations();

        if ($violations !== []) {
            throw LedgerIntegrityException::withFindings($violations);
        }
    }
}
