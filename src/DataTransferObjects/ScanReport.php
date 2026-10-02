<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * The outcome of a scan: how many seals were verified, the count per status, and the failures
 * (at most `maxFindings` of them — `truncated` says whether more were found).
 */
final readonly class ScanReport
{
    /**
     * @param  list<StatusCount>  $counts
     * @param  list<VerificationResult>  $findings
     */
    public function __construct(
        public int $scanned,
        public array $counts,
        public array $findings,
        public bool $truncated,
        public bool $outdatedIsIntact = true,
    ) {}

    /**
     * Whether any failure was found — of the given statuses only, when some are given.
     */
    public function hasFindings(VerificationStatus ...$failOn): bool
    {
        foreach ($this->counts as $count) {
            $matches = $failOn === []
                ? $count->status->isFailure($this->outdatedIsIntact)
                : in_array($count->status, $failOn, true);

            if ($matches && $count->count > 0) {
                return true;
            }
        }

        return false;
    }

    public function count(VerificationStatus $status): int
    {
        foreach ($this->counts as $count) {
            if ($count->status === $status) {
                return $count->count;
            }
        }

        return 0;
    }
}
