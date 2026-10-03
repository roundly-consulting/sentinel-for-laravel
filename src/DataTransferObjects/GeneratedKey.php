<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use JsonSerializable;
use LogicException;
use SensitiveParameter;

/**
 * A freshly generated key. For a config destination `envSnippet` holds the environment lines
 * — **secret material**: print it once, never log it. `publicKey` is the shareable half of an
 * asymmetric key (`base64:`), null for HMAC.
 */
final readonly class GeneratedKey implements JsonSerializable
{
    public function __construct(
        public KeyInfo $info,
        #[SensitiveParameter] public ?string $envSnippet = null,
        public ?string $publicKey = null,
    ) {}

    /**
     * The same redacted view as a dump: `json_encode()`, `response()->json()` and a log
     * context (Monolog normalizes through this) never carry the environment lines.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['info' => $this->info, 'envSnippet' => $this->envSnippet === null ? null : '[redacted]', 'publicKey' => $this->publicKey];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('A generated key cannot be serialized.');
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('A generated key cannot be unserialized.');
    }
}
