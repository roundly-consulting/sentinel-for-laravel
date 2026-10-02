<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * An acknowledgement (or unseal) was refused: no reason, no actor outside the console, or the
 * acknowledgement policy said no.
 */
final class AcknowledgementDeniedException extends SentinelException
{
    public static function reason(): self
    {
        return new self('A reason is required to acknowledge a change.');
    }

    public static function reasonTooLong(int $maximum): self
    {
        return new self("The reason must be at most {$maximum} characters.");
    }

    public static function actorRequired(): self
    {
        return new self('An actor is required to acknowledge a change outside the console.');
    }

    public static function unauthorized(string $code): self
    {
        $shown = preg_match('/^[A-Za-z0-9_.:-]{1,64}$/D', $code) === 1 ? $code : 'denied';

        return new self("The acknowledgement was not authorized ({$shown}).");
    }
}
