<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;

/**
 * The idempotent request completed, but its response cannot be replayed.
 */
final class IdempotentResponseUnavailableException extends IdempotencyException
{
    public static function make(): self
    {
        return new self(IdempotencyRejection::Unavailable);
    }
}
