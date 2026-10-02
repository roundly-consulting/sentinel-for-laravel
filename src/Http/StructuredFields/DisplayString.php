<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

/**
 * An RFC 9651 Display String: Unicode text, serialized as `%"…"` with percent-encoding.
 *
 * @internal
 */
final readonly class DisplayString
{
    public function __construct(public string $value) {}
}
