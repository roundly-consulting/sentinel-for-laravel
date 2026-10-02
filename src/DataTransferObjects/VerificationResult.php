<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * The verdict on one seal of one model. Carries names, never values: `changedAttributes`
 * lists the fields whose keyed tags no longer match (HMAC seals only; null = unknown).
 */
final readonly class VerificationResult
{
    /**
     * @param  list<string>|null  $changedAttributes
     */
    public function __construct(
        public VerificationStatus $status,
        public ?string $reason,
        public string $sealableType,
        public int|string $sealableId,
        public string $seal,
        public ?int $version = null,
        public ?int $ledgerVersion = null,
        public ?string $ring = null,
        public ?string $keyId = null,
        public ?Algorithm $algorithm = null,
        public ?CarbonImmutable $sealedAt = null,
        public ?array $changedAttributes = null,
        public VerificationContext $context = VerificationContext::Api,
        public bool $outdatedIsIntact = true,
    ) {}

    public function isIntact(): bool
    {
        return $this->status->isIntact($this->outdatedIsIntact);
    }

    public function failed(): bool
    {
        return ! $this->isIntact();
    }

    /**
     * Only changed computed fields (`c:*`) — derived data drifted, no sealed column did.
     */
    public function onlyComputedChanged(): bool
    {
        if ($this->status !== VerificationStatus::Tampered || $this->reason !== 'mac' || $this->changedAttributes === null || $this->changedAttributes === []) {
            return false;
        }

        foreach ($this->changedAttributes as $name) {
            if (! str_starts_with($name, 'c:')) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status->value,
            'reason' => $this->reason,
            'sealable_type' => $this->sealableType,
            'sealable_id' => $this->sealableId,
            'seal' => $this->seal,
            'version' => $this->version,
            'ledger_version' => $this->ledgerVersion,
            'ring' => $this->ring,
            'key_id' => $this->keyId,
            'algorithm' => $this->algorithm?->value,
            'sealed_at' => $this->sealedAt?->format('Y-m-d\TH:i:s.u\Z'),
            'changed_attributes' => $this->changedAttributes,
            'context' => $this->context->value,
            'intact' => $this->isIntact(),
        ];
    }
}
