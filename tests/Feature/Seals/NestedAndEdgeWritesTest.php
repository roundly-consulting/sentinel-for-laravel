<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

/**
 * Write paths the dual review found mishandled: deletes of models whose seals are all
 * manual(), deletes of unsaved models.
 */
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
