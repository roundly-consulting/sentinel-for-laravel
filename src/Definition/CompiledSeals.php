<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;

/**
 * Every seal of one model class; the first declared is the default.
 */
final readonly class CompiledSeals
{
    /**
     * @param  class-string  $model
     * @param  array<string, CompiledSeal>  $seals  in declaration order
     */
    public function __construct(
        public string $model,
        public array $seals,
        public string $default,
    ) {}

    /**
     * The named seal (null = the default).
     *
     * @throws SealingMisconfiguredException
     */
    public function get(?string $seal = null): CompiledSeal
    {
        return $this->seals[$seal ?? $this->default] ?? throw SealingMisconfiguredException::unknownSeal($this->model, (string) $seal);
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->seals);
    }

    /**
     * @return list<CompiledSeal>
     */
    public function all(): array
    {
        return array_values($this->seals);
    }

    /**
     * @return list<CompiledSeal>
     */
    public function auto(): array
    {
        return array_values(array_filter($this->seals, static fn (CompiledSeal $seal): bool => $seal->auto));
    }
}
