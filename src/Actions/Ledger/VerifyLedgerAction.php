<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Ledger;

use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Ledger\LedgerVerifier;

/**
 * Verify the ledger itself: checkpoints (sequence, chain, MAC, root), anchors, pending entries
 * and — optionally — every entity's ledger head. Violations fire `LedgerIntegrityViolated`.
 */
final readonly class VerifyLedgerAction
{
    public function __construct(private LedgerVerifier $verifier) {}

    public function execute(LedgerVerifyOptions $options): LedgerReport
    {
        return $this->verifier->verify($options);
    }
}
