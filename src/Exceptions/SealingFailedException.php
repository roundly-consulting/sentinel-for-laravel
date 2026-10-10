<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A seal could not be produced for a structural reason.
 */
final class SealingFailedException extends SentinelException
{
    /**
     * @param  string  $action  what was refused: `sealed` or `verified`
     */
    public static function notPersisted(string $type, string $action = 'sealed'): self
    {
        return new self("A [{$type}] model must be persisted before it can be {$action}.");
    }

    public static function rowVanished(string $type, int|string $id): self
    {
        return new self("The row of [{$type}:{$id}] disappeared between the write and the read-back.");
    }
}
