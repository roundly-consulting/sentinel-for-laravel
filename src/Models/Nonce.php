<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Database\Factories\NonceFactory;
use RoundlyConsulting\Sentinel\Enums\NonceKind;
use RoundlyConsulting\Sentinel\Models\Concerns\StoresUtc;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * A nonce digest: issued by Sentinel (consumed once) or seen from a client (a replay guard).
 * The nonce value itself is never stored.
 *
 * @property int $id
 * @property string $purpose
 * @property string $digest
 * @property NonceKind $kind
 * @property string|null $subject_type
 * @property int|string|null $subject_id
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $consumed_at
 * @property CarbonImmutable $created_at
 */
final class Nonce extends Model
{
    /** @use HasFactory<NonceFactory> */
    use HasFactory;

    use StoresUtc;

    public const UPDATED_AT = null;

    protected $table = 'sentinel_nonces';

    protected $guarded = [];

    public function getConnectionName(): ?string
    {
        return Settings::keyConnection() ?? parent::getConnectionName();
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function subject(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'kind' => NonceKind::class,
            'expires_at' => UtcDateTime::class,
            'consumed_at' => UtcDateTime::class,
            'created_at' => UtcDateTime::class,
        ];
    }

    protected static function newFactory(): NonceFactory
    {
        return NonceFactory::new();
    }
}
