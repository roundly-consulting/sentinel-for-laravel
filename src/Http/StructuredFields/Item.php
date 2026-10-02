<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

/**
 * An RFC 9651 Item: a bare value and its parameters.
 *
 * @internal
 *
 * @phpstan-import-type BareItem from Parameters
 */
final readonly class Item
{
    /**
     * @param  BareItem  $value
     */
    public function __construct(
        public int|float|string|bool|Token|ByteSequence|Date|DisplayString $value,
        public Parameters $parameters = new Parameters,
    ) {}
}
