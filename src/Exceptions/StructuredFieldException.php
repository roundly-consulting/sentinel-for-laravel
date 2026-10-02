<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

/**
 * A structured field value (RFC 9651) that cannot be parsed or serialized. Parsing is strict
 * and fails as a whole — never a partial value.
 */
final class StructuredFieldException extends SentinelException
{
    public static function parse(string $what, int $offset): self
    {
        return new self("Invalid structured field: {$what} at offset {$offset}.");
    }

    public static function serialize(string $what): self
    {
        return new self("Cannot serialize a structured field: {$what}.");
    }
}
