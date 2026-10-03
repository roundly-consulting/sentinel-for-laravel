<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Canonical\FieldValue;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Engine\Inspector;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Stored representations the canonical form must keep apart — or must accept — as Laravel
 * reads them back.
 */
it('detects a zone-less datetime rewritten with an explicit offset (dual-review O-14)', function (string $rewritten): void {
    expect(config('app.timezone'))->toBe('Europe/Bratislava');

    $class = definedBy(static fn ($seals) => $seals->seal('dates')->attributes('number')->datetime('updated_at'));
    CarbonImmutable::setTestNow(CarbonImmutable::parse('2026-01-15 10:00:00', 'Europe/Bratislava'));
    $model = $class::query()->create(['number' => 'd-1']);
    CarbonImmutable::setTestNow();
    $before = $class::query()->findOrFail($model->getKey())->updated_at->toImmutable()->utc();

    $written = corrupt(static fn () => DB::table('invoices')->where('id', $model->getKey())->update(['updated_at' => $rewritten]));
    $after = $class::query()->findOrFail($model->getKey())->updated_at->toImmutable()->utc();

    // PostgreSQL and MySQL normalise on write: the app sees the same instant there.
    if ($written && DriverMatrix::driver() === 'sqlite') {
        expect($after->equalTo($before))->toBeFalse()
            ->and(Sentinel::verify($model)->status)->toBe(VerificationStatus::Tampered);
    } else {
        expect(Sentinel::verify($model)->status)->toBe($after->equalTo($before) ? VerificationStatus::Intact : VerificationStatus::Tampered);
    }
})->with([
    'Z' => ['2026-01-15T10:00:00Z'],
    'an offset' => ['2026-01-15 11:00:00+01:00'],
]);

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

it('seals a date-cast column written with a time, and detects a changed time (dual-review F-5)', function (): void {
    $invoice = invoice(['due_on' => CarbonImmutable::parse('2026-10-31 15:30:00')]);

    expect($invoice->fresh()?->due_on?->format('Y-m-d'))->toBe('2026-10-31')
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);

    $rewritten = corrupt(static fn () => DB::table('invoices')->where('id', $invoice->id)->update(['due_on' => '2026-11-01 09:00:00']));

    expect(Sentinel::verify($invoice)->status)->toBe($rewritten ? VerificationStatus::Tampered : VerificationStatus::Intact);
});

it('types an uncast (auto) column by what each engine returns — a declared type is portable (dual-review O-40)', function (): void {
    $class = definedBy(static function ($seals): void {
        $seals->seal('auto')->attributes('number', 'paid');
        $seals->seal('typed')->attributes('number')->boolean('paid');
    });
    $model = $class::query()->create(['number' => 'p-1', 'paid' => true]);
    $tuple = static fn (string $seal): array => array_column(array_map(
        static fn (FieldValue $field): array => $field->tuple(),
        app(Inspector::class)->values($model, Sentinel::model($class)->definition($seal)),
    ), null, 0)['a:paid'];

    // `auto`: PostgreSQL hands back a PHP bool, SQLite and MySQL an int — documented as
    // engine-dependent; a declared type (or a cast) is the same on every engine.
    expect($tuple('auto'))->toBe(['a:paid', DriverMatrix::driver() === 'pgsql' ? 'bool' : 'int', '1'])
        ->and($tuple('typed'))->toBe(['a:paid', 'bool', '1']);
});
