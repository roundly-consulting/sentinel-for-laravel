<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

/**
 * One call recorded by {@see SentinelFake}: the manager method, its arguments (the request
 * DTO, or the list of scalar arguments) and what the fake returned.
 */
final readonly class RecordedCall
{
    /**
     * @param  object|list<mixed>  $arguments
     */
    public function __construct(
        public string $method,
        public object|array $arguments,
        public mixed $result = null,
    ) {}
}
