<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

/**
 * Stored representations the canonical form must keep apart — or must accept — as Laravel
 * reads them back.
 */
/**
 * Laravel's `timestamp` cast: the column holds a datetime, the attribute reads as a Unix int.
 */
final class TimestampCastInvoice extends Model implements Sealable
{
    use HasSeals;

    protected $table = 'invoices';

    protected $guarded = [];

    protected $casts = ['updated_at' => 'timestamp'];

    public static function defineSeals(SealBuilder $seals): void
    {
        $seals->seal('ts')->attributes('number', 'updated_at');
    }
}

it('seals a datetime column that uses the timestamp cast (dual-review O-16)', function (): void {
    $model = TimestampCastInvoice::query()->create(['number' => 't-1']);

    expect(is_int($model->updated_at))->toBeTrue()
        ->and(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact);

    DB::table('invoices')->where('id', $model->getKey())->update(['updated_at' => '2020-01-01 00:00:00']);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Tampered);
});
