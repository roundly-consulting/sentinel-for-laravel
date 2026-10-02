<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * Two writers raced for the same seal version, or two checkpoint runs for the same ledger
 * entries (unique index / compare-and-swap). The losing transaction rolls back; retrying it
 * is safe.
 */
final class ConcurrentSealException extends SentinelException
{
    public static function versionConflict(string $type, int|string $id, string $seal): self
    {
        return new self("The seal [{$seal}] of [{$type}:{$id}] was changed concurrently; retry the write.");
    }

    public static function checkpointConflict(string $connection): self
    {
        return new self("Another checkpoint run raced this one on connection [{$connection}]; retry.");
    }
}
