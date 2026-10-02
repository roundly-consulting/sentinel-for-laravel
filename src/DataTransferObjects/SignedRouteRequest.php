<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * A single-use signed URL for a named route.
 */
final readonly class SignedRouteRequest
{
    /**
     * @param  array<string, mixed>  $parameters
     */
    public function __construct(
        public string $name,
        public array $parameters = [],
        public ?int $ttl = null,
    ) {}
}
