<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Definition;

use Closure;

/**
 * A declared computed field: its resolver and optional declared type.
 *
 * @internal
 */
final readonly class ComputedDeclaration
{
    public function __construct(
        public Closure $resolver,
        public ?SealType $type,
    ) {}
}
