<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use BackedEnum;
use ReflectionEnum;

/**
 * The declared type of an attribute from the model's cast (plan §4.2.4). Floats have no
 * inferred type — engines disagree on them — so they must be declared.
 *
 * @internal
 */
final class Inference
{
    /**
     * @return SealType|null null when the cast cannot be sealed without a declaration (floats)
     */
    public static function fromCast(?string $cast): ?SealType
    {
        if ($cast === null || $cast === '') {
            return SealType::auto();
        }

        $base = strtolower(explode(':', $cast, 2)[0]);
        $class = explode(':', $cast, 2)[0];

        if ($base === 'decimal') {
            $scale = (int) (explode(':', $cast, 2)[1] ?? 0);

            return $scale <= SealType::MAX_SCALE ? SealType::decimal(max(0, $scale)) : null;
        }

        return match (true) {
            in_array($base, ['int', 'integer', 'timestamp'], true) => SealType::integer(),
            in_array($base, ['bool', 'boolean'], true) => SealType::boolean(),
            in_array($base, ['float', 'double', 'real'], true) => null,
            in_array($base, ['string', 'hashed', 'encrypted'], true) => SealType::string(),
            in_array($base, ['date', 'immutable_date'], true) => SealType::date(),
            in_array($base, ['datetime', 'immutable_datetime', 'custom_datetime'], true) => SealType::datetime(),
            in_array($base, ['array', 'json', 'object', 'collection'], true) => SealType::json(),
            enum_exists($class) && is_subclass_of($class, BackedEnum::class) => (string) (new ReflectionEnum($class))->getBackingType() === 'int'
                ? SealType::integer()
                : SealType::string(),
            str_ends_with($class, '\AsStringable') => SealType::string(),
            str_contains($class, '\AsEncrypted') => SealType::string(),
            str_ends_with($class, '\AsArrayObject'), str_ends_with($class, '\AsCollection'),
            str_ends_with($class, '\AsEnumArrayObject'), str_ends_with($class, '\AsEnumCollection'), str_ends_with($class, '\AsFluent') => SealType::json(),
            default => SealType::auto(),
        };
    }
}
