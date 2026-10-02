<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\StructuredFields;

/**
 * An RFC 9651 Token (an unquoted identifier such as `application/json` or `sha-256`).
 *
 * @internal
 */
final readonly class Token
{
    public function __construct(public string $value) {}
}
