<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

/**
 * Write paths the dual review found mishandled: a listener that saves the same model again
 * inside its write, deletes of models whose seals are all manual(), deletes of unsaved models.
 */
it('seals a model whose created listener saves it again, without a false alarm (dual-review O-7)', function (): void {
    Event::fake([TamperDetected::class]);
    $class = definedBy(static fn ($seals) => $seals->seal('default')->attributes('number', 'amount'));
    $class::created(static function (Model $model): void {
        $model->forceFill(['number' => 'INV-'.$model->getKey()])->saveQuietly();
    });

    $model = $class::query()->create(['amount' => '5.00']);

    expect($model->number)->toBe('INV-'.$model->getKey())
        ->and(Sentinel::verify($class::query()->findOrFail($model->getKey()))->status)->toBe(VerificationStatus::Intact)
        ->and(LedgerEntry::query()->where('sealable_id', $model->getKey())->pluck('event')->map(static fn (SealEvent $event): string => $event->value)->all())->toBe(['sealed']);

    Event::assertNotDispatched(TamperDetected::class);
});

it('re-seals once after an updated listener saves the same row through another instance (dual-review O-7)', function (): void {
    Event::fake([TamperDetected::class]);
    $class = definedBy(static fn ($seals) => $seals->seal('default')->attributes('number', 'amount', 'note'));
    $class::updated(static function (Model $model) use ($class): void {
        if ($model->wasChanged('amount')) {
            $class::query()->findOrFail($model->getKey())->forceFill(['note' => 'amount changed'])->save();
        }
    });

    $model = $class::query()->create(['number' => 'x', 'amount' => '5.00']);
    $model->update(['amount' => '6.00']);
    $fresh = $class::query()->findOrFail($model->getKey());

    expect($fresh->note)->toBe('amount changed')
        ->and(Sentinel::verify($fresh)->status)->toBe(VerificationStatus::Intact)
        ->and(LedgerEntry::query()->where('sealable_id', $model->getKey())->count())->toBe(2);

    Event::assertNotDispatched(TamperDetected::class);
});

it('never treats another new row of the same class as a nested write (dual-review O-7)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('default')->attributes('number', 'amount'));
    $class::creating(static function (Model $model) use ($class): void {
        if ($model->getAttribute('number') === 'parent') {
            $class::query()->create(['number' => 'child', 'amount' => '1.00']);
        }
    });

    $parent = $class::query()->create(['number' => 'parent', 'amount' => '2.00']);
    $child = $class::query()->where('number', 'child')->firstOrFail();

    expect(Sentinel::verify($parent)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($child)->status)->toBe(VerificationStatus::Intact);
});

it('tombstones a hard delete of a model whose seals are all manual() (dual-review O-15 / F-2)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('m')->attributes('number', 'amount')->manual());
    $model = $class::query()->create(['number' => 'm-1', 'amount' => '5.00']);
    Sentinel::seal($model);

    $model->delete();

    expect(DB::table('sentinel_seals')->where('sealable_id', $model->getKey())->exists())->toBeFalse()
        ->and(LedgerEntry::query()->where('sealable_id', $model->getKey())->orderByDesc('version')->firstOrFail()->event)->toBe(SealEvent::Deleted)
        ->and(Sentinel::verifyLedger()->has(LedgerFindingKind::EntityDeleted))->toBeFalse();
});

it('deletes a never-sealed manual() model without writing anything (dual-review O-15 / F-2)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('m')->attributes('number', 'amount')->manual());
    $model = $class::query()->create(['number' => 'm-2', 'amount' => '5.00']);

    expect($model->delete())->toBeTrue()
        ->and(LedgerEntry::query()->where('sealable_id', $model->getKey())->exists())->toBeFalse();
});

it('returns null for a delete of an unsaved model, as Eloquent does (dual-review F-6)', function (): void {
    // A soft-deleting model whose seal has a computed field: the soft-delete re-seal path.
    expect((new Invoice(['number' => 'n']))->delete())->toBeNull()
        ->and((new Invoice(['number' => 'n']))->forceDelete())->toBeNull()
        ->and(LedgerEntry::query()->count())->toBe(0);
});

it('never touches a live row\'s seal when an unsaved instance carrying its key is deleted (dual-review F-6)', function (): void {
    $record = record();

    expect((new $record)->forceFill(['id' => $record->id])->delete())->toBeNull()
        ->and(Sentinel::verify($record)->status)->toBe(VerificationStatus::Intact)
        ->and(LedgerEntry::query()->where('sealable_id', $record->id)->orderByDesc('version')->firstOrFail()->event)->toBe(SealEvent::Sealed);
});

it('re-seals a soft delete whose deleting listener saved the row (dual-review O-7)', function (): void {
    Invoice::deleting(static function (Invoice $invoice): void {
        if (! $invoice->isForceDeleting()) {
            $invoice->forceFill(['number' => 'ARCHIVED'])->saveQuietly();
        }
    });
    $invoice = invoice();

    $invoice->delete();
    $trashed = Invoice::withTrashed()->findOrFail($invoice->id);

    // `identity` covers neither deleted_at nor a computed field: only the nested write re-seals it.
    expect($trashed->number)->toBe('ARCHIVED')
        ->and(Sentinel::verify($trashed, 'identity')->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($trashed, 'financial')->status)->toBe(VerificationStatus::Intact);
});
