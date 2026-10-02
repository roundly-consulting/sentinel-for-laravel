<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A seal could not be produced for a structural reason.
 */
final class SealingFailedException extends SentinelException
{
    public static function notPersisted(string $type): self
    {
        return new self("A [{$type}] model must be persisted before it can be sealed.");
    }

    public static function rowVanished(string $type, int|string $id): self
    {
        return new self("The row of [{$type}:{$id}] disappeared between the write and the read-back.");
    }
}
