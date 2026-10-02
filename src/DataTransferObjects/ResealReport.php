<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * The outcome of a bulk (re-)seal: rows re-sealed, acknowledged, left alone (with the
 * non-intact ones among them listed) and failed.
 */
final readonly class ResealReport
{
    /**
     * @param  list<VerificationResult>  $skippedResults
     */
    public function __construct(
        public int $resealed = 0,
        public int $acknowledged = 0,
        public int $skipped = 0,
        public int $failed = 0,
        public array $skippedResults = [],
        public bool $dryRun = false,
    ) {}
}
