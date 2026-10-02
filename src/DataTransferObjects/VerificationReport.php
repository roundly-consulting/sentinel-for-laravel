<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;

/**
 * Several verdicts (every seal of a model, or many models).
 */
final readonly class VerificationReport
{
    /**
     * @param  list<VerificationResult>  $results
     */
    public function __construct(public array $results) {}

    public function allIntact(): bool
    {
        return $this->failures() === [];
    }

    /**
     * @return list<VerificationResult>
     */
    public function failures(): array
    {
        return array_values(array_filter($this->results, static fn (VerificationResult $result): bool => $result->failed()));
    }

    public function count(VerificationStatus $status): int
    {
        return count(array_filter($this->results, static fn (VerificationResult $result): bool => $result->status === $status));
    }

    /**
     * @return list<StatusCount>
     */
    public function counts(): array
    {
        $counts = [];

        foreach (VerificationStatus::cases() as $status) {
            $count = $this->count($status);

            if ($count > 0) {
                $counts[] = new StatusCount($status, $count);
            }
        }

        return $counts;
    }

    /**
     * @throws TamperedModelException when any verdict is a failure
     */
    public function throwIfTampered(): void
    {
        $failures = $this->failures();

        if ($failures !== []) {
            throw count($failures) === 1 ? TamperedModelException::forResult($failures[0]) : TamperedModelException::many($failures);
        }
    }
}
