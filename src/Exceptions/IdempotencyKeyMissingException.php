<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;

/**
 * An Idempotency-Key header is required on this endpoint.
 */
final class IdempotencyKeyMissingException extends IdempotencyException
{
    public static function make(): self
    {
        return new self(IdempotencyRejection::Missing);
    }
}
