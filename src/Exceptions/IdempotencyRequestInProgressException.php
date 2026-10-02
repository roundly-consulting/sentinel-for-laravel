<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;

/**
 * A request with the same idempotency key is still being processed (409 + Retry-After).
 */
final class IdempotencyRequestInProgressException extends IdempotencyException
{
    public static function retryAfter(int $seconds): self
    {
        return (new self(IdempotencyRejection::InProgress))->withRetryAfter($seconds);
    }
}
