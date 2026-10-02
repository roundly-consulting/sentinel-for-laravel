<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A database key row does not match its encrypted envelope (a column was edited, the
 * envelope swapped or corrupted). The key is treated as unknown until fixed.
 */
final class KeyIntegrityException extends SentinelException
{
    public static function envelopeMismatch(string $ring, string $keyId, string $field): self
    {
        return new self("The stored key [{$ring}:{$keyId}] failed its integrity check ({$field}).");
    }
}
