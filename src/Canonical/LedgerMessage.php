<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * The canonical ledger-entry document (`sentinel.ledger/1`, plan §4.7.1) covered by the
 * entry's own MAC — so the audit fields (actor, reason, changed attributes, previous status)
 * cannot be edited in the database without the entry failing verification. FROZEN.
 *
 * @internal
 */
final readonly class LedgerMessage
{
    public const string VERSION = 'sentinel.ledger/1';

    /**
     * @param  list<string>|null  $changed
     */
    public function __construct(
        public string $context,
        public string $type,
        public string $id,
        public string $seal,
        public int $version,
        public SealEvent $event,
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public ?string $sealMac,
        public ?string $previous,
        public ?array $changed,
        public ?VerificationStatus $previousStatus,
        public ?string $actor,
        public ?string $reason,
        public CarbonImmutable $at,
    ) {}

    public function bytes(): string
    {
        $changed = $this->changed;

        if ($changed !== null) {
            sort($changed, SORT_STRING);
        }

        return Jcs::encode([
            'actor' => $this->actor,
            'alg' => $this->algorithm->value,
            'at' => Clock::iso($this->at),
            'changed' => $changed,
            'ctx' => $this->context,
            'event' => $this->event->value,
            'id' => $this->id,
            'kid' => $this->keyId,
            'mac' => $this->sealMac,
            'prev' => $this->previous,
            'previous_status' => $this->previousStatus?->value,
            'reason' => $this->reason,
            'ring' => $this->ring,
            'seal' => $this->seal,
            'type' => $this->type,
            'v' => self::VERSION,
            'ver' => (string) $this->version,
        ]);
    }
}
