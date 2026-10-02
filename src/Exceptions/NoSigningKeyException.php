<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A ring has no key that may sign right now (none configured, only public material, or the
 * current key is revoked, retired or not yet active). Verify-only nodes see this on purpose.
 */
final class NoSigningKeyException extends SentinelException
{
    public static function forRing(string $ring): self
    {
        return new self("Key ring [{$ring}] has no active signing key. Generate one with `php artisan sentinel:key:generate --ring={$ring}`.");
    }
}
