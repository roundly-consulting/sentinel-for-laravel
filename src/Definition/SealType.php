<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use RoundlyConsulting\Sentinel\Enums\TypeKind;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSealDefinitionException;

/**
 * A declared field type — the `tag` a manifest stores for a field (`str`, `dec:2`, `flt:3`,
 * `json`, …). Declared in seal definitions (`computed('total', $fn, SealType::decimal(2))`)
 * or inferred from the model's casts.
 */
final readonly class SealType
{
    public const int MAX_SCALE = 30;

    private function __construct(
        public TypeKind $kind,
        public ?int $scale = null,
    ) {}

    public static function string(): self
    {
        return new self(TypeKind::String);
    }

    public static function integer(): self
    {
        return new self(TypeKind::Integer);
    }

    public static function boolean(): self
    {
        return new self(TypeKind::Boolean);
    }

    public static function decimal(int $scale): self
    {
        return new self(TypeKind::Decimal, self::assertScale($scale));
    }

    public static function float(int $scale): self
    {
        return new self(TypeKind::Float, self::assertScale($scale));
    }

    public static function datetime(): self
    {
        return new self(TypeKind::DateTime);
    }

    public static function date(): self
    {
        return new self(TypeKind::Date);
    }

    public static function json(): self
    {
        return new self(TypeKind::Json);
    }

    public static function binary(): self
    {
        return new self(TypeKind::Binary);
    }

    /**
     * The runtime-typed default: the tag follows the raw value (int, bool, string, null).
     */
    public static function auto(): self
    {
        return new self(TypeKind::Auto);
    }

    /**
     * An encrypted-cast column sealed as its plaintext (decrypted through the model's cast).
     */
    public static function plaintext(): self
    {
        return new self(TypeKind::Plaintext);
    }

    /**
     * Parse a stored manifest tag (`dec:2`). Returns null for anything that is not a
     * declarable tag of format v1.
     */
    public static function tryFromTag(string $tag): ?self
    {
        if (preg_match('/^(dec|flt):(\d{1,2})$/D', $tag, $m) === 1) {
            $scale = (int) $m[2];

            if ($scale > self::MAX_SCALE || $m[2] !== (string) $scale) {
                return null;
            }

            return new self(TypeKind::from($m[1]), $scale);
        }

        $kind = TypeKind::tryFrom($tag);

        return $kind === null || $kind->hasScale() || ! $kind->isDeclarable() ? null : new self($kind);
    }

    public function tag(): string
    {
        return $this->kind->hasScale()
            ? $this->kind->value.':'.$this->scale
            : $this->kind->value;
    }

    public function equals(self $other): bool
    {
        return $this->tag() === $other->tag();
    }

    private static function assertScale(int $scale): int
    {
        if ($scale < 0 || $scale > self::MAX_SCALE) {
            throw InvalidSealDefinitionException::invalidScale($scale, self::MAX_SCALE);
        }

        return $scale;
    }
}
