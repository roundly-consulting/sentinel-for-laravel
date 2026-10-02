<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Carbon\CarbonImmutable;
use LogicException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;

/**
 * A resolved key: its ring, `kid`, pinned algorithm, validated material and **effective**
 * status (dates and the revocation list already folded in).
 *
 * The algorithm here is the only one a seal or signature is ever checked with — never the
 * algorithm stored on a seal row or sent in an HTTP `alg` parameter. Custom key stores build
 * these; nothing else should.
 */
final readonly class SealingKey
{
    public function __construct(
        public string $ring,
        public string $keyId,
        private KeyMaterial $material,
        public KeyStatus $status = KeyStatus::Active,
        public string $driver = 'config',
        public ?CarbonImmutable $activatesAt = null,
        public ?CarbonImmutable $signsUntil = null,
        public ?CarbonImmutable $verifiesUntil = null,
        public ?CarbonImmutable $revokedAt = null,
        public ?string $label = null,
        public ?string $ownerType = null,
        public int|string|null $ownerId = null,
    ) {}

    public function algorithm(): Algorithm
    {
        return $this->material->algorithm;
    }

    public function material(): KeyMaterial
    {
        return $this->material;
    }

    /**
     * Active status and private/secret material.
     */
    public function canSign(): bool
    {
        return $this->status->canSign() && $this->material->canSign();
    }

    public function canVerify(): bool
    {
        return $this->status->canVerify();
    }

    public function withStatus(KeyStatus $status): self
    {
        return new self(
            $this->ring, $this->keyId, $this->material, $status, $this->driver, $this->activatesAt,
            $this->signsUntil, $this->verifiesUntil, $this->revokedAt, $this->label, $this->ownerType, $this->ownerId,
        );
    }

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return [
            'ring' => $this->ring,
            'keyId' => $this->keyId,
            'algorithm' => $this->algorithm()->value,
            'status' => $this->status->value,
            'driver' => $this->driver,
            'material' => '[redacted]',
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('A sealing key cannot be serialized.');
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('A sealing key cannot be unserialized.');
    }
}
