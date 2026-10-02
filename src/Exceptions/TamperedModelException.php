<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;

/**
 * A model is not intact: `verifyOrFail()` failed, or an Eloquent write was refused because
 * the row was changed outside the application (acknowledge the change first). The message
 * names the model and status; the full result is attached.
 */
final class TamperedModelException extends SentinelException
{
    /**
     * @param  list<VerificationResult>  $results
     */
    private function __construct(string $message, private readonly array $results)
    {
        parent::__construct($message);
    }

    public static function forResult(VerificationResult $result): self
    {
        return new self(
            "The seal [{$result->seal}] of [{$result->sealableType}:{$result->sealableId}] is not intact ({$result->status->value}"
            .($result->reason === null ? '' : ": {$result->reason}").'). Acknowledge the change before writing.',
            [$result],
        );
    }

    /**
     * @param  list<VerificationResult>  $results
     */
    public static function many(array $results): self
    {
        return new self(count($results).' sealed model(s) are not intact; nothing was written.', $results);
    }

    public function result(): ?VerificationResult
    {
        return $this->results[0] ?? null;
    }

    /**
     * @return list<VerificationResult>
     */
    public function results(): array
    {
        return $this->results;
    }
}
