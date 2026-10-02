<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use Throwable;

/**
 * The result of `Sentinel::idempotency()->run()` cannot be stored for replays (it must be
 * JSON-encodable). The key was released, so the call may be retried.
 */
final class IdempotentResultException extends SentinelException
{
    public static function notEncodable(Throwable $previous): self
    {
        return new self('An idempotent result must be JSON-encodable to be replayed.', 0, $previous);
    }
}
