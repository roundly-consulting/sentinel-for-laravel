<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use Closure;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSealDefinitionException;

/**
 * One seal's declaration. Fields are an explicit allow-list (never `*`): attributes typed by
 * the model's casts unless overridden, plus computed values. Every method returns `$this`.
 */
final class SealDefinitionBuilder
{
    /** @var array<string, SealType|null> column => declared type (null = infer from casts) */
    private array $attributes = [];

    /** @var array<string, ComputedDeclaration> */
    private array $computed = [];

    /** @var list<string> */
    private array $problems = [];

    private ?string $ring = null;

    /** @var list<string>|null */
    private ?array $acceptRings = null;

    /** @var list<Algorithm>|null */
    private ?array $algorithms = null;

    private ?bool $strict = null;

    private ?bool $auto = null;

    private ?Reaction $verifyOnRetrieve = null;

    private bool $verifyOnRetrieveSet = false;

    private ?bool $fieldTags = null;

    private ?Closure $scope = null;

    private ?TamperedWritePolicy $onTamperedWrite = null;

    private ?string $using = null;

    public function __construct(private readonly string $name) {}

    public function attributes(string ...$columns): self
    {
        foreach ($columns as $column) {
            if (array_key_exists($column, $this->attributes)) {
                $this->problems[] = "seal [{$this->name}] lists the field [a:{$column}] twice";

                continue;
            }

            $this->attributes[$column] = null;
        }

        return $this;
    }

    public function string(string ...$columns): self
    {
        return $this->typed(SealType::string(), array_values($columns));
    }

    public function integer(string ...$columns): self
    {
        return $this->typed(SealType::integer(), array_values($columns));
    }

    public function boolean(string ...$columns): self
    {
        return $this->typed(SealType::boolean(), array_values($columns));
    }

    public function decimal(string $column, int $scale): self
    {
        return $this->scaled($column, $scale, static fn (int $scale): SealType => SealType::decimal($scale));
    }

    /**
     * A float column, rounded half-even to `$scale` digits (lossy by declaration).
     */
    public function float(string $column, int $scale): self
    {
        return $this->scaled($column, $scale, static fn (int $scale): SealType => SealType::float($scale));
    }

    public function datetime(string ...$columns): self
    {
        return $this->typed(SealType::datetime(), array_values($columns));
    }

    public function date(string ...$columns): self
    {
        return $this->typed(SealType::date(), array_values($columns));
    }

    public function json(string ...$columns): self
    {
        return $this->typed(SealType::json(), array_values($columns));
    }

    public function binary(string ...$columns): self
    {
        return $this->typed(SealType::binary(), array_values($columns));
    }

    /**
     * Seal an encrypted-cast column as its decrypted plaintext (the ciphertext is sealed by
     * default).
     */
    public function plaintext(string ...$columns): self
    {
        return $this->typed(SealType::plaintext(), array_values($columns));
    }

    /**
     * A value computed from the model (`static fn (Invoice $invoice): array => …`), typed by
     * its PHP type unless `$as` declares one. Floats must be declared.
     */
    public function computed(string $name, Closure $resolver, ?SealType $as = null): self
    {
        if (array_key_exists($name, $this->computed)) {
            $this->problems[] = "seal [{$this->name}] declares the computed field [c:{$name}] twice";

            return $this;
        }

        $this->computed[$name] = new ComputedDeclaration($resolver, $as);

        return $this;
    }

    public function ring(string $ring): self
    {
        $this->ring = $ring;

        return $this;
    }

    /**
     * Further rings whose existing seals still verify (ring migrations).
     */
    public function acceptRings(string ...$rings): self
    {
        $this->acceptRings = array_values($rings);

        return $this;
    }

    public function algorithms(Algorithm ...$algorithms): self
    {
        $this->algorithms = array_values($algorithms);

        return $this;
    }

    /**
     * A missing seal is a finding (the default).
     */
    public function strict(): self
    {
        $this->strict = true;

        return $this;
    }

    /**
     * A missing seal is merely "unsealed".
     */
    public function lenient(): self
    {
        $this->strict = false;

        return $this;
    }

    /**
     * Seal automatically on Eloquent writes (the default).
     */
    public function auto(): self
    {
        $this->auto = true;

        return $this;
    }

    /**
     * Seal only explicitly (`Sentinel::for($model)->seal()`).
     */
    public function manual(): self
    {
        $this->auto = false;

        return $this;
    }

    public function verifyOnRetrieve(?Reaction $reaction = null): self
    {
        $this->verifyOnRetrieve = $reaction;
        $this->verifyOnRetrieveSet = true;

        return $this;
    }

    public function fieldTags(bool $enabled = true): self
    {
        $this->fieldTags = $enabled;

        return $this;
    }

    /**
     * A per-model scope bound into the MAC (e.g. the tenant id), so a seal can never be
     * replayed across scopes.
     */
    public function scope(Closure $resolver): self
    {
        $this->scope = $resolver;

        return $this;
    }

    public function onTamperedWrite(TamperedWritePolicy $policy): self
    {
        $this->onTamperedWrite = $policy;

        return $this;
    }

    /**
     * Apply a reusable `SealDefinition` class first; inline calls win.
     *
     * @param  class-string  $definition
     */
    public function using(string $definition): self
    {
        $this->using = $definition;

        return $this;
    }

    /**
     * This builder laid over a base (the `using()` definition): inline fields and options win.
     *
     * @internal
     */
    public function over(self $base): self
    {
        $merged = clone $base;
        $merged->problems = [...$base->problems, ...$this->problems];

        foreach ($this->attributes as $column => $type) {
            $merged->attributes[$column] = $type ?? $merged->attributes[$column] ?? null;
        }

        foreach ($this->computed as $name => $computed) {
            $merged->computed[$name] = $computed;
        }

        $merged->ring = $this->ring ?? $base->ring;
        $merged->acceptRings = $this->acceptRings ?? $base->acceptRings;
        $merged->algorithms = $this->algorithms ?? $base->algorithms;
        $merged->strict = $this->strict ?? $base->strict;
        $merged->auto = $this->auto ?? $base->auto;
        $merged->verifyOnRetrieveSet = $this->verifyOnRetrieveSet || $base->verifyOnRetrieveSet;
        $merged->verifyOnRetrieve = $this->verifyOnRetrieveSet ? $this->verifyOnRetrieve : $base->verifyOnRetrieve;
        $merged->fieldTags = $this->fieldTags ?? $base->fieldTags;
        $merged->scope = $this->scope ?? $base->scope;
        $merged->onTamperedWrite = $this->onTamperedWrite ?? $base->onTamperedWrite;
        $merged->using = null;

        return $merged;
    }

    /** @internal */
    public function name(): string
    {
        return $this->name;
    }

    /**
     * @internal
     *
     * @return array<string, SealType|null>
     */
    public function declaredAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * @internal
     *
     * @return array<string, ComputedDeclaration>
     */
    public function declaredComputed(): array
    {
        return $this->computed;
    }

    /**
     * @internal
     *
     * @return list<string>
     */
    public function problems(): array
    {
        return $this->problems;
    }

    /** @internal */
    public function declaredRing(): ?string
    {
        return $this->ring;
    }

    /**
     * @internal
     *
     * @return list<string>
     */
    public function declaredAcceptRings(): array
    {
        return $this->acceptRings ?? [];
    }

    /**
     * @internal
     *
     * @return list<Algorithm>|null
     */
    public function declaredAlgorithms(): ?array
    {
        return $this->algorithms;
    }

    /** @internal */
    public function isStrict(): bool
    {
        return $this->strict ?? true;
    }

    /** @internal */
    public function isAuto(): bool
    {
        return $this->auto ?? true;
    }

    /** @internal */
    public function retrieveReaction(): ?Reaction
    {
        return $this->verifyOnRetrieve;
    }

    /** @internal */
    public function verifiesOnRetrieve(): bool
    {
        return $this->verifyOnRetrieveSet;
    }

    /** @internal */
    public function declaredFieldTags(): ?bool
    {
        return $this->fieldTags;
    }

    /** @internal */
    public function declaredScope(): ?Closure
    {
        return $this->scope;
    }

    /** @internal */
    public function declaredPolicy(): ?TamperedWritePolicy
    {
        return $this->onTamperedWrite;
    }

    /** @internal */
    public function usedDefinition(): ?string
    {
        return $this->using;
    }

    /**
     * @param  list<string>  $columns
     */
    private function typed(SealType $type, array $columns): self
    {
        foreach ($columns as $column) {
            $this->attributes[$column] = $type;
        }

        return $this;
    }

    /**
     * @param  Closure(int): SealType  $make
     */
    private function scaled(string $column, int $scale, Closure $make): self
    {
        try {
            $this->attributes[$column] = $make($scale);
        } catch (InvalidSealDefinitionException) {
            $this->problems[] = "seal [{$this->name}] declares [a:{$column}] with scale {$scale}; use 0..".SealType::MAX_SCALE;
        }

        return $this;
    }
}
