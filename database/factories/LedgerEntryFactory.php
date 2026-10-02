<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Structurally valid but unsigned ledger entries — for negative tests only.
 *
 * @extends Factory<LedgerEntry>
 */
final class LedgerEntryFactory extends Factory
{
    protected $model = LedgerEntry::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'sealable_type' => 'sealable',
            'sealable_id' => $this->faker->unique()->numberBetween(1, 1_000_000),
            'seal' => 'default',
            'event' => SealEvent::Sealed,
            'version' => 1,
            'ring' => 'default',
            'key_id' => 'test-default',
            'algorithm' => 'hmac-sha256',
            'seal_mac' => str_repeat('A', 43),
            'entry_mac' => str_repeat('B', 43),
            'occurred_at' => Clock::now(),
        ];
    }

    public function forSealable(Model $sealable, string $seal): static
    {
        return $this->state([
            'sealable_type' => $sealable->getMorphClass(),
            'sealable_id' => $sealable->getKey(),
            'seal' => $seal,
        ]);
    }

    public function tombstone(SealEvent $event = SealEvent::Deleted): static
    {
        return $this->state(['event' => $event, 'seal_mac' => null]);
    }
}
