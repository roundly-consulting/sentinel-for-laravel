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

    public static function notSealable(string $class): self
    {
        return new self("[{$class}] is not sealable: it must implement RoundlyConsulting\\Sentinel\\Contracts\\Sealable and use RoundlyConsulting\\Sentinel\\Concerns\\HasSeals.");
    }

    public static function unknownSeal(string $class, string $seal): self
    {
        $shown = preg_match('/^[a-z0-9_.-]{1,64}$/D', $seal) === 1 ? $seal : '(invalid)';

        return new self("[{$class}] declares no seal [{$shown}].");
    }

    public static function saveOverridden(string $class, string $method): self
    {
        return new self("[{$class}] overrides {$method}() without sealing; call \$this->persistSealed(fn () => parent::{$method}(...)) from the override.");
    }
}
