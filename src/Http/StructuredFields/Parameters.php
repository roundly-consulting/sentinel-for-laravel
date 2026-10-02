<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

/**
 * Ordered RFC 9651 parameters (`;key=value`). Keys are lowercase identifiers, never numeric,
 * so the PHP array keeps them as strings and in order; a repeated key keeps its first
 * position with the last value (RFC 9651 §4.2.3.2).
 *
 * @internal
 *
 * @phpstan-type BareItem int|float|string|bool|Token|ByteSequence|Date|DisplayString
 */
final readonly class Parameters
{
    /**
     * @param  array<string, BareItem>  $values
     */
    public function __construct(public array $values = []) {}

    /**
     * @return BareItem|null
     */
    public function get(string $key): int|float|string|bool|Token|ByteSequence|Date|DisplayString|null
    {
        return $this->values[$key] ?? null;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values);
    }

    /**
     * @param  BareItem  $value
     */
    public function with(string $key, int|float|string|bool|Token|ByteSequence|Date|DisplayString $value): self
    {
        return new self([...$this->values, $key => $value]);
    }

    public function isEmpty(): bool
    {
        return $this->values === [];
    }
}
