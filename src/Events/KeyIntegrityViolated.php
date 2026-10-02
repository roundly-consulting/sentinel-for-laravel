<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Events;

/**
 * A stored key failed its envelope integrity check — someone edited `sentinel_keys`.
 * Dispatched synchronously when the key is read.
 */
final readonly class KeyIntegrityViolated
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public string $driver,
    ) {}
}
