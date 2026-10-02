<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;

/**
 * One ledger-verification finding. Identifiers and a short machine-readable detail only —
 * never values.
 */
final readonly class LedgerFinding
{
    public function __construct(
        public LedgerFindingKind $kind,
        public ?int $seq,
        public ?int $entryId,
        public ?string $sealableType,
        public int|string|null $sealableId,
        public ?string $seal,
        public string $detail,
        public ?string $connection = null,
    ) {}

    public function isViolation(): bool
    {
        return $this->kind->isViolation();
    }

    /**
     * @return array<string, int|string|null>
     */
    public function toArray(): array
    {
        return [
            'kind' => $this->kind->value,
            'connection' => $this->connection,
            'seq' => $this->seq,
            'entry_id' => $this->entryId,
            'sealable_type' => $this->sealableType,
            'sealable_id' => $this->sealableId,
            'seal' => $this->seal,
            'detail' => $this->detail,
        ];
    }
}
