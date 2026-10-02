<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Structurally valid but unsigned checkpoints — for negative tests only.
 *
 * @extends Factory<Checkpoint>
 */
final class CheckpointFactory extends Factory
{
    protected $model = Checkpoint::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'seq' => $this->faker->unique()->numberBetween(1, 1_000_000),
            'first_entry_id' => 1,
            'last_entry_id' => 1,
            'entries' => 1,
            'root' => str_repeat('R', 43),
            'previous_digest' => null,
            'ring' => 'default',
            'key_id' => 'test-default',
            'algorithm' => 'hmac-sha256',
            'mac' => str_repeat('M', 43),
            'created_at' => Clock::now(),
        ];
    }
}
