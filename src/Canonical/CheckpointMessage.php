<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * The canonical checkpoint document (`sentinel.checkpoint/1`, plan §4.7.2): a keyed,
 * chained digest over a batch of ledger entries. FROZEN.
 *
 * @internal
 */
final readonly class CheckpointMessage
{
    public const string VERSION = 'sentinel.checkpoint/1';

    public function __construct(
        public string $context,
        public int $sequence,
        public int $firstEntryId,
        public int $lastEntryId,
        public int $entries,
        public string $root,
        public ?string $previous,
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public CarbonImmutable $at,
    ) {}

    public function bytes(): string
    {
        return Jcs::encode([
            'alg' => $this->algorithm->value,
            'at' => Clock::iso($this->at),
            'ctx' => $this->context,
            'first' => (string) $this->firstEntryId,
            'kid' => $this->keyId,
            'last' => (string) $this->lastEntryId,
            'n' => (string) $this->entries,
            'prev' => $this->previous,
            'ring' => $this->ring,
            'root' => $this->root,
            'seq' => (string) $this->sequence,
            'v' => self::VERSION,
        ]);
    }
}
