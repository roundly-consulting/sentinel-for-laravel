<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Models;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Database\Factories\IdempotencyKeyFactory;
use RoundlyConsulting\Sentinel\Models\Concerns\StoresUtc;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * One idempotency key: a digest, the payload fingerprint, the processing lease and — once
 * completed — the (encrypted) response. Written through the store's atomic statements only.
 *
 * @property int $id
 * @property string $key_digest
 * @property string $scope
 * @property string $fingerprint
 * @property string $status processing|completed
 * @property string $owner_token
 * @property CarbonImmutable $locked_until
 * @property int|null $response_status
 * @property string|null $response
 * @property bool $replayable
 * @property CarbonImmutable|null $completed_at
 * @property CarbonImmutable $expires_at
 * @property CarbonImmutable|null $created_at
 * @property CarbonImmutable|null $updated_at
 */
final class IdempotencyKey extends Model
{
    /** @use HasFactory<IdempotencyKeyFactory> */
    use HasFactory;

    use StoresUtc;

    public const string PROCESSING = 'processing';

    public const string COMPLETED = 'completed';

    protected $table = 'sentinel_idempotency_keys';

    protected $guarded = [];

    protected $hidden = ['response', 'owner_token'];

    public function getConnectionName(): ?string
    {
        return Settings::keyConnection() ?? parent::getConnectionName();
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'response_status' => 'integer',
            'replayable' => 'boolean',
            'locked_until' => UtcDateTime::class,
            'completed_at' => UtcDateTime::class,
            'expires_at' => UtcDateTime::class,
            'created_at' => UtcDateTime::class,
            'updated_at' => UtcDateTime::class,
        ];
    }

    protected static function newFactory(): IdempotencyKeyFactory
    {
        return IdempotencyKeyFactory::new();
    }
}
