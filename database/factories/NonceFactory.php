<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use RoundlyConsulting\Sentinel\Enums\NonceKind;
use RoundlyConsulting\Sentinel\Models\Nonce;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Nonce digests in each state.
 *
 * @extends Factory<Nonce>
 */
final class NonceFactory extends Factory
{
    protected $model = Nonce::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'purpose' => 'test',
            'digest' => $this->faker->unique()->regexify('[A-Za-z0-9_-]{43}'),
            'kind' => NonceKind::Issued,
            'expires_at' => Clock::now()->addMinutes(15),
            'created_at' => Clock::now(),
        ];
    }

    public function issued(): static
    {
        return $this->state(['kind' => NonceKind::Issued]);
    }

    public function seen(): static
    {
        return $this->state(['kind' => NonceKind::Seen]);
    }

    public function consumed(): static
    {
        return $this->state(['consumed_at' => Clock::now()]);
    }

    public function expired(): static
    {
        return $this->state(['expires_at' => Clock::now()->subSecond()]);
    }
}
