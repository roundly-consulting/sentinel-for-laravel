<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Enums\HealthStatus;

/**
 * Every installation check, in a stable order (`Sentinel::check()`).
 */
final readonly class HealthReport
{
    /**
     * @param  list<HealthCheck>  $checks
     */
    public function __construct(public array $checks) {}

    /**
     * Any check failed (warnings do not fail the report).
     */
    public function failed(): bool
    {
        return $this->failures() !== [];
    }

    /**
     * @return list<HealthCheck>
     */
    public function failures(): array
    {
        return $this->with(HealthStatus::Failure);
    }

    /**
     * @return list<HealthCheck>
     */
    public function warnings(): array
    {
        return $this->with(HealthStatus::Warning);
    }

    public function get(string $name): ?HealthCheck
    {
        foreach ($this->checks as $check) {
            if ($check->name === $name) {
                return $check;
            }
        }

        return null;
    }

    /**
     * @return array{failed: bool, checks: list<array{name: string, status: string, message: string}>}
     */
    public function toArray(): array
    {
        return [
            'failed' => $this->failed(),
            'checks' => array_map(static fn (HealthCheck $check): array => $check->toArray(), $this->checks),
        ];
    }

    /**
     * @return list<HealthCheck>
     */
    private function with(HealthStatus $status): array
    {
        return array_values(array_filter($this->checks, static fn (HealthCheck $check): bool => $check->status === $status));
    }
}
