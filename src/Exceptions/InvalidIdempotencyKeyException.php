<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;

/**
 * The Idempotency-Key header is not a valid key.
 */
final class InvalidIdempotencyKeyException extends IdempotencyException
{
    public static function make(): self
    {
        return new self(IdempotencyRejection::Invalid);
    }
}
