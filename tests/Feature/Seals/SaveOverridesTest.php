<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Enums\PersistOperation;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides\SafeOverride;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides\SubclassBypass;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides\SubclassOverride;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides\UnsafeDeleteOverride;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides\UnsafeOverride;

/**
 * §10 item 17 — a model whose save() / delete() would skip sealing is refused; every override
 * that still reaches the sealed write path is accepted (defect D-2: a subclass calling
 * parent::save() reaches HasSeals' own save(), and the guard must not need the source file).
 */
it('accepts overrides that go through persistSealed()', function (): void {
    $model = SafeOverride::query()->create(['name' => '  padded  ']);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact)
        ->and($model->name)->toBe('padded');

    $model->delete();

    expect(LedgerEntry::query()->where('event', 'deleted')->count())->toBe(1);
});

it('accepts a subclass whose save() and delete() call parent::', function (): void {
    $model = SubclassOverride::query()->create(['name' => 'shouted']);

    expect($model->name)->toBe('SHOUTED')
        ->and(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact);

    $model->update(['name' => 'again']);

    expect(Sentinel::verify($model)->isIntact())->toBeTrue()
        ->and(Seal::query()->where('sealable_id', $model->getKey())->value('version'))->toBe(2);

    $model->delete();

    expect(LedgerEntry::query()->where('sealable_id', $model->getKey())->where('event', 'deleted')->count())->toBe(1);
});

it('accepts an override whose source file cannot be read', function (): void {
    // eval()'d code has no readable source file — like a host that ships stripped artefacts.
    $class = 'EvaluatedOverride'.bin2hex(random_bytes(4));
    eval('final class '.$class.' extends '.Model::class.' implements '.Sealable::class.' {
        use '.HasSeals::class.';
        protected $table = "plain_records";
        protected $guarded = [];
        public static function defineSeals('.SealBuilder::class.' $seals): void { $seals->seal("default")->attributes("name"); }
        public function save(array $options = []): bool { return $this->persistSealed(fn () => '.Model::class.'::save($options)) === true; }
        public function delete(): ?bool { return $this->persistSealed(fn () => '.Model::class.'::delete(), '.PersistOperation::class.'::Delete); }
    }');

    $model = $class::query()->create(['name' => 'evaluated']);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact);

    $model->delete();

    expect(LedgerEntry::query()->where('sealable_id', $model->getKey())->where('event', 'deleted')->count())->toBe(1);
});

it('refuses a save() override that skips sealing before anything is written', function (string $class): void {
    expect(fn () => $class::query()->create(['name' => 'unsealed']))
        ->toThrow(SealingMisconfiguredException::class, 'overrides save()')
        ->and(DB::table('plain_records')->count())->toBe(0)
        ->and(Seal::query()->count())->toBe(0);
})->with([
    'in the class using the trait' => [UnsafeOverride::class],
    'in a subclass' => [SubclassBypass::class],
]);

it('refuses a delete() override that skips sealing before anything is deleted', function (): void {
    $model = UnsafeDeleteOverride::query()->create(['name' => 'kept']);

    expect(fn () => $model->delete())->toThrow(SealingMisconfiguredException::class, 'overrides delete()')
        ->and(DB::table('plain_records')->where('id', $model->getKey())->exists())->toBeTrue()
        ->and(LedgerEntry::query()->where('event', 'deleted')->count())->toBe(0)
        ->and(Sentinel::verify($model)->isIntact())->toBeTrue();
});

it('refuses a bypassing subclass delete() as well', function (): void {
    $model = SubclassOverride::query()->create(['name' => 'base']);
    $bypass = SubclassBypass::query()->withoutGlobalScopes()->findOrFail($model->getKey());

    expect(fn () => $bypass->delete())->toThrow(SealingMisconfiguredException::class, 'overrides delete()')
        ->and(DB::table('plain_records')->where('id', $model->getKey())->exists())->toBeTrue();
});

it('lets quiet writes through the sealed path, and refuses nothing under the fake that production accepts', function (): void {
    $model = SubclassOverride::query()->create(['name' => 'quiet']);
    $model->name = 'quieter';
    $model->saveQuietly();

    expect(Sentinel::verify($model)->isIntact())->toBeTrue();

    $fake = Sentinel::fake();
    $faked = SubclassOverride::query()->create(['name' => 'faked']);

    $fake->assertSealed($faked);

    expect(fn () => UnsafeOverride::query()->create(['name' => 'x']))->toThrow(SealingMisconfiguredException::class, 'overrides save()');
});

it('refuses an unsafe override reached with model events muted (dual-review O-17)', function (Closure $write): void {
    $record = UnsafeOverride::query()->getModel()->newInstance(['name' => 'quiet']);

    expect(fn () => $write($record))->toThrow(SealingMisconfiguredException::class, 'outside the sealed write path')
        ->and(DB::table('plain_records')->where('name', 'quiet')->exists())->toBeFalse();
})->with([
    'saveQuietly()' => [static fn (Model $model): mixed => $model->saveQuietly()],
    'withoutEvents()' => [static fn (Model $model): mixed => Model::withoutEvents(static fn (): mixed => $model->save())],
]);

it('refuses an unsafe update or delete override reached with model events muted (dual-review O-17)', function (): void {
    $sealed = SafeOverride::query()->create(['name' => 'kept']);
    $update = UnsafeOverride::query()->findOrFail($sealed->getKey());
    $update->name = 'unsealed';
    $delete = UnsafeDeleteOverride::query()->findOrFail($sealed->getKey());

    expect(fn () => $update->saveQuietly())->toThrow(SealingMisconfiguredException::class, 'outside the sealed write path')
        ->and(fn () => $delete->deleteQuietly())->toThrow(SealingMisconfiguredException::class, 'outside the sealed write path')
        ->and(DB::table('plain_records')->where('id', $sealed->getKey())->value('name'))->toBe('kept')
        ->and(LedgerEntry::query()->where('event', 'deleted')->count())->toBe(0);
});

it('keeps every quiet write path of a sealable working (dual-review O-17)', function (): void {
    $record = record();
    $record->name = 'quiet';
    $record->saveQuietly();
    $record->updateQuietly(['code' => 'Q1']);
    $record->incrementQuietly('count');
    $record->touchQuietly();
    $copy = $record->replicateQuietly();
    $copy->save();

    expect(Sentinel::verify($record->fresh())->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($copy)->status)->toBe(VerificationStatus::Intact)
        ->and($record->deleteQuietly())->toBeTrue()
        ->and(LedgerEntry::query()->where('sealable_id', $record->getKey())->orderByDesc('version')->firstOrFail()->event->value)->toBe('deleted');
});
