<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A Sentinel table holds a value no Sentinel code writes (an edited or corrupted row).
 */
final class CorruptRecordException extends SentinelException
{
    public static function invalidDatetime(string $column): self
    {
        return new self("The stored value of [{$column}] is not a UTC datetime.");
    }
}
