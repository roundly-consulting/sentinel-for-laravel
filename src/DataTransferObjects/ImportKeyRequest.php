<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use LogicException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use SensitiveParameter;

/**
 * Import existing key material into a ring's database store — a partner's public key or
 * agreed HMAC secret (verify-only), or your own key pair moving from the environment into the
 * database (`signing: true`). `material` is a PEM block or `base64:<standard base64>`; private
 * or secret material signs only when imported with `signing: true`. Never dumped or
 * serialized.
 */
final readonly class ImportKeyRequest
{
    public function __construct(
        public string $ring,
        public string $keyId,
        public Algorithm $algorithm,
        #[SensitiveParameter] public string $material,
        public bool $signing = false,
        public ?CarbonImmutable $activatesAt = null,
        public ?Model $owner = null,
        public ?string $label = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'ring' => $this->ring, 'keyId' => $this->keyId, 'algorithm' => $this->algorithm->value, 'material' => '[redacted]',
            'signing' => $this->signing, 'activatesAt' => $this->activatesAt, 'label' => $this->label,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('A key import request cannot be serialized.');
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('A key import request cannot be unserialized.');
    }
}
