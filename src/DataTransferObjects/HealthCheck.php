<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\HealthStatus;

/**
 * One installation check: a stable name (`signing_keys`, `tables`, …), its status and a
 * message for an operator — never key material, never a database key's id.
 */
final readonly class HealthCheck
{
    public function __construct(
        public string $name,
        public HealthStatus $status,
        public string $message,
    ) {}

    /**
     * @return array{name: string, status: string, message: string}
     */
    public function toArray(): array
    {
        return ['name' => $this->name, 'status' => $this->status->value, 'message' => $this->message];
    }
}
