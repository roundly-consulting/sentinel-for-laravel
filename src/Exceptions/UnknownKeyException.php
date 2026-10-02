<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * No key with that `kid` exists in that ring. Key ids resolve only inside their own ring —
 * a kid of another ring is unknown here, by design.
 */
final class UnknownKeyException extends SentinelException
{
    public static function inRing(string $ring, string $keyId): self
    {
        $shown = preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $keyId) === 1 ? $keyId : '(invalid)';

        return new self("Key ring [{$ring}] has no key [{$shown}].");
    }
}
