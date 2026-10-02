<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

/**
 * An RFC 9651 Date: integer seconds since the Unix epoch, serialized as `@1659578233`.
 *
 * @internal
 */
final readonly class Date
{
    public function __construct(public int $timestamp) {}
}
