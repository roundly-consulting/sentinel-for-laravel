<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use Closure;
use RoundlyConsulting\Sentinel\Enums\TypeKind;

/**
 * One field of a compiled seal: `a:<column>` (read back from the database) or
 * `c:<name>` (computed from the model), with its declared type.
 */
final readonly class ManifestField
{
    public function __construct(
        public string $name,
        public SealType $type,
        public ?string $column = null,
        public ?Closure $resolver = null,
    ) {}

    public static function attribute(string $column, SealType $type): self
    {
        return new self('a:'.$column, $type, $column);
    }

    public static function computed(string $name, SealType $type, Closure $resolver): self
    {
        return new self('c:'.$name, $type, null, $resolver);
    }

    public function isComputed(): bool
    {
        return str_starts_with($this->name, 'c:');
    }

    public function isPlaintext(): bool
    {
        return $this->type->kind === TypeKind::Plaintext;
    }

    public function tag(): string
    {
        return $this->type->tag();
    }
}
