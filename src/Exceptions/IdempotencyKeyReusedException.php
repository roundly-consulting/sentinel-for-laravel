<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;

/**
 * The idempotency key was already used with a different request.
 */
final class IdempotencyKeyReusedException extends IdempotencyException
{
    public static function make(): self
    {
        return new self(IdempotencyRejection::Reused);
    }
}
