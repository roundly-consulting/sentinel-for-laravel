<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The type kinds of canonical field values (`sentinel.seal/1`). The value is the tag stem
 * written into every field tuple; `dec` and `flt` carry their scale as `dec:N` / `flt:N`.
 *
 * `auto` and `plain` are declared-only: they appear in a manifest, never in a tuple — the
 * tuple carries the runtime tag the value resolved to. `null` is runtime-only.
 */
enum TypeKind: string
{
    use Helpers;

    case Auto = 'auto';
    case String = 'str';
    case Integer = 'int';
    case Decimal = 'dec';
    case Float = 'flt';
    case Boolean = 'bool';
    case DateTime = 'dt';
    case Date = 'date';
    case Json = 'json';
    case Binary = 'bin';
    case Null = 'null';
    case Plaintext = 'plain';

    public function hasScale(): bool
    {
        return $this === self::Decimal || $this === self::Float;
    }

    /**
     * Whether the kind may be declared on a field (everything except the runtime-only
     * `null`).
     */
    public function isDeclarable(): bool
    {
        return $this !== self::Null;
    }
}
