<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use LogicException;
use SensitiveParameter;

/**
 * The outcome of a rotation: the new signing key, the key it replaced (now verify-only), and
 * — for a config ring — the environment lines to apply (secret).
 */
final readonly class RotationResult
{
    public function __construct(
        public KeyInfo $current,
        public ?KeyInfo $previous = null,
        #[SensitiveParameter] public ?string $envSnippet = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return ['current' => $this->current, 'previous' => $this->previous, 'envSnippet' => $this->envSnippet === null ? null : '[redacted]'];
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        throw new LogicException('A rotation result cannot be serialized.');
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException('A rotation result cannot be unserialized.');
    }
}
