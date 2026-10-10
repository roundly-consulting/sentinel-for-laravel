<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Carbon\CarbonImmutable;
use JsonSerializable;
use SensitiveParameter;

/**
 * The authoritative content of a database key, held encrypted in the row's `envelope`
 * ({@see KeyEnvelope}): every field, the label included (`sentinel.key/2`; a legacy
 * `sentinel.key/1` envelope carries no label, so its label is read from the column).
 *
 * @internal
 */
final readonly class EnvelopeData implements JsonSerializable
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
        public ?string $label = null,
    ) {}

    public function with(
        ?string $status = null,
        ?CarbonImmutable $signsUntil = null,
        ?CarbonImmutable $verifiesUntil = null,
        ?CarbonImmutable $revokedAt = null,
    ): self {
        return new self(
            $this->ring, $this->keyId, $this->algorithm, $this->material, $this->public, $status ?? $this->status, $this->activatesAt,
            $signsUntil ?? $this->signsUntil, $verifiesUntil ?? $this->verifiesUntil, $revokedAt ?? $this->revokedAt, $this->owner, $this->label,
        );
    }

    /**
     * The same redacted view as a dump: never the material.
     *
     * @return array<string, string|null>
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @return array<string, string|null>
     */
    public function __debugInfo(): array
    {
        return ['ring' => $this->ring, 'keyId' => $this->keyId, 'algorithm' => $this->algorithm, 'material' => '[redacted]', 'status' => $this->status];
    }
}
