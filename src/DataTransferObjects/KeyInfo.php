<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Keys\SealingKey;

/**
 * What may be known about a key without its material: identity, algorithm, effective status
 * and SP 800-57 usage periods. Safe to log, render and serialize.
 */
final readonly class KeyInfo
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        public KeyStatus $status,
        public string $driver,
        public bool $canSign,
        public ?CarbonImmutable $activatesAt = null,
        public ?CarbonImmutable $signsUntil = null,
        public ?CarbonImmutable $verifiesUntil = null,
        public ?CarbonImmutable $revokedAt = null,
        public ?string $label = null,
        public ?string $ownerType = null,
        public int|string|null $ownerId = null,
    ) {}

    public static function fromKey(SealingKey $key): self
    {
        return new self(
            $key->ring, $key->keyId, $key->algorithm(), $key->status, $key->driver, $key->canSign(),
            $key->activatesAt, $key->signsUntil, $key->verifiesUntil, $key->revokedAt, $key->label, $key->ownerType, $key->ownerId,
        );
    }
}
