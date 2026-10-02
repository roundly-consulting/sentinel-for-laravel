<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A nonce purpose outside `[a-z0-9][a-z0-9:._-]{0,127}`.
 */
final class InvalidPurposeException extends SentinelException
{
    public static function forPurpose(string $purpose): self
    {
        $shown = preg_match('/^[A-Za-z0-9:._-]{1,128}$/D', $purpose) === 1 ? $purpose : '(invalid)';

        return new self("[{$shown}] is not a nonce purpose; use [a-z0-9][a-z0-9:._-]{0,127}.");
    }
}
