<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Carbon\CarbonImmutable;
use SensitiveParameter;

/**
 * The authoritative content of a database key (`sentinel.key/1`), held encrypted in the
 * row's `envelope`.
 *
 * @internal
 */
final readonly class EnvelopeData
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public string $algorithm,
        #[SensitiveParameter] public ?string $material,
        public ?string $public,
        public string $status,
        public CarbonImmutable $activatesAt,
        public ?CarbonImmutable $signsUntil = null,
        public ?CarbonImmutable $verifiesUntil = null,
        public ?CarbonImmutable $revokedAt = null,
        public ?string $owner = null,
    ) {}

    public function with(
        ?string $status = null,
        ?CarbonImmutable $signsUntil = null,
        ?CarbonImmutable $verifiesUntil = null,
        ?CarbonImmutable $revokedAt = null,
    ): self {
        return new self(
            $this->ring, $this->keyId, $this->algorithm, $this->material, $this->public, $status ?? $this->status, $this->activatesAt,
            $signsUntil ?? $this->signsUntil, $verifiesUntil ?? $this->verifiesUntil, $revokedAt ?? $this->revokedAt, $this->owner,
        );
    }

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return ['ring' => $this->ring, 'keyId' => $this->keyId, 'algorithm' => $this->algorithm, 'material' => '[redacted]', 'status' => $this->status];
    }
}
