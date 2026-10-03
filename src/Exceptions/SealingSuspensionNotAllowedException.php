<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

final class SealingSuspensionNotAllowedException extends SentinelException
{
    public static function disabled(): self
    {
        return new self('Sentinel::withoutSealing() is off: sentinel.sealing.allow_suspension is false or not set (set SENTINEL_ALLOW_SUSPENSION=true to opt in).');
    }
}
