<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Keys\EnvelopeData;
use RoundlyConsulting\Sentinel\Keys\KeyEnvelope;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Database keys with valid, freshly generated material and a matching envelope.
 *
 * @extends Factory<Key>
 */
final class KeyFactory extends Factory
{
    protected $model = Key::class;

    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'ring' => 'default',
            'kid' => 'test-'.strtolower($this->faker->unique()->bothify('????????')),
            'algorithm' => Algorithm::HmacSha256->value,
            'status' => KeyStatus::Active->value,
            'activates_at' => Clock::now()->subMinute(),
        ];
    }

    public function configure(): static
    {
        // Material is generated for the final algorithm and sealed into the envelope together
        // with every bound column, so a factory key always opens cleanly.
        return $this->afterMaking(static function (Key $key): void {
            $material = KeyMaterial::generate(Algorithm::from($key->algorithm));

            app(KeyEnvelope::class)->apply($key, new EnvelopeData(
                $key->ring, $key->kid, $key->algorithm, $material->encodedPrivate(), $material->encodedPublic(), $key->status,
                $key->activates_at, $key->signs_until, $key->verifies_until, $key->revoked_at,
                $key->owner_type === null ? null : $key->owner_type.':'.$key->owner_id,
            ));
        });
    }

    public function ring(string $ring): static
    {
        return $this->state(['ring' => $ring]);
    }

    public function hmac(Algorithm $algorithm = Algorithm::HmacSha256): static
    {
        return $this->state(['algorithm' => $algorithm->value]);
    }

    public function ed25519(): static
    {
        return $this->state(['algorithm' => Algorithm::Ed25519->value]);
    }

    public function ecdsaP256(): static
    {
        return $this->state(['algorithm' => Algorithm::EcdsaP256Sha256->value]);
    }

    public function verifyOnly(): static
    {
        return $this->state(['status' => KeyStatus::VerifyOnly->value]);
    }

    public function revoked(): static
    {
        return $this->state(['status' => KeyStatus::Revoked->value, 'revoked_at' => Clock::now()->subSecond()]);
    }

    public function retired(): static
    {
        return $this->state(['status' => KeyStatus::Retired->value, 'verifies_until' => Clock::now()->subSecond()]);
    }

    public function pending(): static
    {
        return $this->state(['activates_at' => Clock::now()->addDay()]);
    }
}
