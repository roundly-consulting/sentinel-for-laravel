<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

/**
 * An RFC 9651 Byte Sequence: raw bytes, serialized as `:base64:`.
 *
 * @internal
 */
final readonly class ByteSequence
{
    public function __construct(public string $bytes) {}
}
