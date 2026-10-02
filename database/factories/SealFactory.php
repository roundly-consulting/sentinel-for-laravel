<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Structurally valid but **unsigned** seal rows — for malformed-row and negative tests.
 * Real seals only ever come from the engine.
 *
 * @extends Factory<Seal>
 */
final class SealFactory extends Factory
{
    protected $model = Seal::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'sealable_type' => 'sealable',
            'sealable_id' => $this->faker->unique()->numberBetween(1, 1_000_000),
            'seal' => 'default',
            'format' => 1,
            'ring' => 'default',
            'key_id' => 'test-default',
            'algorithm' => 'hmac-sha256',
            'version' => 1,
            'previous_digest' => null,
            'mac' => str_repeat('A', 43),
            'manifest' => [['a:name', 'str']],
            'field_tags' => null,
            'event' => SealEvent::Sealed,
            'sealed_at' => Clock::now(),
        ];
    }

    /**
     * Point the row at a model's seal (the plan's `->for()`; `for()` itself is Laravel's
     * relationship helper).
     */
    public function forSealable(Model $sealable, string $seal): static
    {
        return $this->state([
            'sealable_type' => $sealable->getMorphClass(),
            'sealable_id' => $sealable->getKey(),
            'seal' => $seal,
        ]);
    }
}
