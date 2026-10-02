<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Carbon\CarbonImmutable;
use LogicException;
use SensitiveParameter;

/**
 * A freshly issued nonce. The value is shown once — Sentinel stores only its SHA-256.
 */
final readonly class IssuedNonce
{
    public function __construct(
        #[SensitiveParameter] public string $value,
        public string $purpose,
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * @return array<string, string>
     */
    public function __debugInfo(): array
    {
        return ['value' => '[redacted]', 'purpose' => $this->purpose, 'expiresAt' => $this->expiresAt->format('Y-m-d\TH:i:s.u\Z')];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('An issued nonce cannot be serialized.');
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('An issued nonce cannot be unserialized.');
    }
}
