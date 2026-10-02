<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

final class SealingSuspensionNotAllowedException extends SentinelException
{
    public static function disabled(): self
    {
        return new self('Sentinel::withoutSealing() is disabled (sentinel.sealing.allow_suspension = false).');
    }
}
