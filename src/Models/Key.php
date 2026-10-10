<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Database\Factories\KeyFactory;
use RoundlyConsulting\Sentinel\Models\Concerns\StoresUtc;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * A database-driver key. The `envelope` (Sentinel's own AES-256-GCM ciphertext, hidden from
 * serialization) is authoritative: it binds ring, kid, algorithm, material, status, dates,
 * owner and label, and every plain column here exists only for querying — an edited column is
 * caught as an integrity failure, never trusted. (A legacy `sentinel.key/1` envelope, written
 * before 1.2, does not bind the label: `sentinel:key:reseal` upgrades it.)
 *
 * @property int $id
 * @property string $ring
 * @property string $kid
 * @property string $algorithm
 * @property string $status
 * @property string $envelope
 * @property CarbonImmutable $activates_at
 * @property CarbonImmutable|null $signs_until
 * @property CarbonImmutable|null $verifies_until
 * @property CarbonImmutable|null $revoked_at
 * @property string|null $revocation_reason
 * @property string|null $label
 * @property string|null $owner_type
 * @property int|string|null $owner_id
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
final class Key extends Model
{
    /** @use HasFactory<KeyFactory> */
    use HasFactory;

    use StoresUtc;

    protected $table = 'sentinel_keys';

    protected $guarded = [];

    protected $hidden = ['envelope'];

    public function getConnectionName(): ?string
    {
        return Settings::keyConnection() ?? parent::getConnectionName();
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function owner(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'activates_at' => UtcDateTime::class,
            'signs_until' => UtcDateTime::class,
            'verifies_until' => UtcDateTime::class,
            'revoked_at' => UtcDateTime::class,
            'created_at' => UtcDateTime::class,
            'updated_at' => UtcDateTime::class,
        ];
    }

    protected static function newFactory(): KeyFactory
    {
        return KeyFactory::new();
    }
}
