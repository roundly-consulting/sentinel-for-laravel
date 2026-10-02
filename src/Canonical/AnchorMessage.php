<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * The canonical anchor payload (`sentinel.anchor/1`, plan §4.7.3) published to external
 * stores. It carries the checkpoint's own MAC, so a tampered anchor is detectable and a
 * forged "ahead" anchor can only raise a false alarm. FROZEN.
 *
 * @internal
 */
final readonly class AnchorMessage
{
    public const string VERSION = 'sentinel.anchor/1';

    public function __construct(
        public string $connection,
        public int $sequence,
        public string $root,
        public CarbonImmutable $at,
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public string $mac,
    ) {}

    public function bytes(): string
    {
        return Jcs::encode([
            'alg' => $this->algorithm->value,
            'at' => Clock::iso($this->at),
            'conn' => $this->connection,
            'kid' => $this->keyId,
            'mac' => $this->mac,
            'ring' => $this->ring,
            'root' => $this->root,
            'seq' => (string) $this->sequence,
            'v' => self::VERSION,
        ]);
    }
}
