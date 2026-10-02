<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * Sentinel was asked to work with something that is not set up for it: an unconfigured key
 * ring, a model that is not sealable, a seal that is not declared.
 */
final class SealingMisconfiguredException extends SentinelException
{
    public static function unknownRing(string $ring): self
    {
        $shown = preg_match('/^[a-z0-9_-]{1,64}$/D', $ring) === 1 ? $ring : '(invalid)';

        return new self("Key ring [{$shown}] is not configured under sentinel.keys.rings.");
    }
}
