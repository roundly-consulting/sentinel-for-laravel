<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Idempotency keys in each state (the response payload is left to the test).
 *
 * @extends Factory<IdempotencyKey>
 */
final class IdempotencyKeyFactory extends Factory
{
    protected $model = IdempotencyKey::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'key_digest' => $this->faker->unique()->regexify('[A-Za-z0-9_-]{43}'),
            'scope' => 'ip:127.0.0.1',
            'fingerprint' => $this->faker->regexify('[A-Za-z0-9_-]{43}'),
            'status' => IdempotencyKey::PROCESSING,
            'owner_token' => $this->faker->regexify('[A-Za-z0-9_-]{43}'),
            'locked_until' => Clock::now()->addMinute(),
            'replayable' => true,
            'expires_at' => Clock::now()->addDay(),
        ];
    }

    public function processing(): static
    {
        return $this->state(['status' => IdempotencyKey::PROCESSING]);
    }

    public function completed(): static
    {
        return $this->state(['status' => IdempotencyKey::COMPLETED, 'completed_at' => Clock::now(), 'response_status' => 201]);
    }

    public function expired(): static
    {
        return $this->state(['expires_at' => Clock::now()->subSecond(), 'locked_until' => Clock::now()->subMinute()]);
    }
}
