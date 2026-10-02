<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A job behind the `Idempotent` middleware released or failed itself: its run did not
 * complete, so the key is given back. Control flow only — the middleware catches it.
 *
 * @internal
 */
final class JobNotCompletedException extends SentinelException
{
    public static function make(): self
    {
        return new self('The job released or failed itself; its idempotency key is given back.');
    }
}
