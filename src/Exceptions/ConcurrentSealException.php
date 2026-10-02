<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * Two writers raced for the same seal version (unique index / version compare-and-swap).
 * The losing transaction rolls back; retrying it is safe.
 */
final class ConcurrentSealException extends SentinelException
{
    public static function versionConflict(string $type, int|string $id, string $seal): self
    {
        return new self("The seal [{$seal}] of [{$type}:{$id}] was changed concurrently; retry the write.");
    }
}
