<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use Throwable;

/**
 * The result of `Sentinel::idempotency()->run()` cannot be stored for replays (it must be
 * JSON-encodable). The callback did run, so its key is completed as unreplayable: a repeat
 * with the same key is refused (`IdempotentResponseUnavailableException`, 409) instead of
 * running the callback — and its side effect — a second time. Return an encodable result.
 */
final class IdempotentResultException extends SentinelException
{
    public static function notEncodable(Throwable $previous): self
    {
        return new self('An idempotent result must be JSON-encodable to be replayed; the callback ran and its key is now completed without a replayable result.', 0, $previous);
    }
}
