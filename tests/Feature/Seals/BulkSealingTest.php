<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use RoundlyConsulting\Sentinel\Actions\Seals\ResealModelsAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

function rotateDefaultRing(): string
{
    config()->set('sentinel.keys.rings.default.driver', 'chain');
    config()->set('sentinel.keys.rings.default.drivers', ['database', 'config']);
    app(KeyStoreManager::class)->flush();

    return Sentinel::keys()->ring()->generate(Algorithm::HmacSha384, 'rotated-key')->info->keyId;
}

function latestEvent(Invoice $invoice, string $seal = 'financial'): ?SealEvent
{
    return LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', $seal)->orderByDesc('version')->first()?->event;
}

it('scans every row, soft-deleted ones included, and keeps the failures', function (): void {
    $intact = invoice();
    $tampered = invoice();
    $trashed = invoice();
    $trashed->delete();
    DB::table('invoices')->where('id', $tampered->id)->update(['amount' => '0.00']);
    Invoice::query()->insert(['number' => 'raw']);

    $report = Sentinel::model(Invoice::class)->scan();

    expect($report->scanned)->toBe(8)
        ->and($report->count(VerificationStatus::Intact))->toBe(5)
        ->and($report->count(VerificationStatus::Unsealed))->toBe(1)
        ->and($report->count(VerificationStatus::Tampered))->toBe(1)
        ->and($report->count(VerificationStatus::Missing))->toBe(1)
        ->and($report->count(VerificationStatus::Stale))->toBe(0)
        ->and(array_map(static fn ($finding): string => $finding->status->value, $report->findings))->toBe(['tampered', 'missing'])
        ->and($report->hasFindings())->toBeTrue()
        ->and($report->hasFindings(VerificationStatus::Stale))->toBeFalse()
        ->and($report->truncated)->toBeFalse()
        ->and([$intact->id])->not->toBeEmpty();

    $limited = Sentinel::scan(new ScanOptions([Invoice::class], 'financial', 1, true, limit: 2, maxFindings: 0));

    expect($limited->scanned)->toBe(2)
        ->and($limited->findings)->toBe([])
        ->and($limited->truncated)->toBeTrue();
});

it('checks the schema before scanning when asked', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('ghost')->attributes('number', 'no_such_column'));

    expect(fn () => Sentinel::scan(new ScanOptions([$class], checkSchema: true)))->toThrow(SealingMisconfiguredException::class, 'no_such_column')
        ->and(Sentinel::scan(new ScanOptions([Invoice::class], checkSchema: true))->scanned)->toBe(0);
});

it('re-seals intact and outdated rows with the current key (event rotated)', function (): void {
    $invoice = invoice();
    $old = Sentinel::verify($invoice)->keyId;
    $new = rotateDefaultRing();

    $dry = Sentinel::model(Invoice::class)->reseal(dryRun: true);
    $report = Sentinel::model(Invoice::class)->reseal(fromKeyId: $old);

    expect($dry->resealed)->toBe(2)
        ->and($dry->dryRun)->toBeTrue()
        ->and(Sentinel::verify($invoice)->keyId)->toBe($new)
        ->and($report->resealed)->toBe(2)
        ->and(latestEvent($invoice))->toBe(SealEvent::Rotated)
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact)
        // Already on the current key: nothing left to do.
        ->and(Sentinel::model(Invoice::class)->reseal()->resealed)->toBe(0)
        ->and(Sentinel::model(Invoice::class)->reseal(fromKeyId: $old)->resealed)->toBe(0);
});

it('never launders: re-sealing skips and reports rows that are not intact (§10 item 14)', function (): void {
    $intact = invoice();
    $tampered = invoice();
    $missing = invoice();
    DB::table('invoices')->where('id', $tampered->id)->update(['amount' => '0.00']);
    Seal::query()->where('sealable_id', $missing->id)->where('seal', 'financial')->delete();
    rotateDefaultRing();

    $report = Sentinel::model(Invoice::class)->reseal('financial');

    expect($report->resealed)->toBe(1)
        ->and($report->skipped)->toBe(2)
        ->and(array_map(static fn ($result): string => $result->status->value, $report->skippedResults))->toBe(['tampered', 'missing'])
        ->and(Sentinel::verify($tampered)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::verify($missing)->status)->toBe(VerificationStatus::Missing)
        ->and([$intact->id])->not->toBeEmpty();

    $acknowledged = Sentinel::model(Invoice::class)->reseal('financial', acknowledgeReason: 'INC-12 reviewed');

    expect($acknowledged->acknowledged)->toBe(2)
        ->and(Sentinel::verify($tampered)->status)->toBe(VerificationStatus::Intact)
        ->and(latestEvent($tampered))->toBe(SealEvent::Acknowledged)
        ->and(Sentinel::verify($missing)->status)->toBe(VerificationStatus::Intact);
});

it('re-seals only outdated rows when asked', function (): void {
    $invoice = invoice();
    $class = definedBy(static fn ($seals) => $seals->seal('changing')->attributes('number'));
    $model = $class::query()->create(['number' => 'n-1']);
    $class::$define = static fn ($seals) => $seals->seal('changing')->attributes('number', 'currency');
    app()->forgetInstance(DefinitionRegistry::class);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Outdated)
        ->and(Sentinel::model($class)->reseal(onlyOutdated: true)->resealed)->toBe(1)
        ->and(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::model(Invoice::class)->reseal(onlyOutdated: true)->resealed)->toBe(0)
        ->and(Sentinel::reseal(new ResealOptions(Invoice::class, upgradeFormat: true))->resealed)->toBe(0)
        ->and([$invoice->id])->not->toBeEmpty();
});

it('re-verifies under the row lock before rotating', function (): void {
    $invoice = invoice();
    rotateDefaultRing();
    $action = app(ResealModelsAction::class);

    // Tampered between the scan and the locked re-check: the locked verdict wins.
    $rotate = new ReflectionMethod($action, 'rotate');
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

    expect($rotate->invoke($action, $invoice, app(DefinitionRegistry::class)->seal($invoice), null)->status)->toBe(VerificationStatus::Tampered);
});

it('acknowledges every row a query selects (resealWhere)', function (): void {
    $admin = User::query()->create(['name' => 'admin']);
    $draft = invoice(['status' => 'draft']);
    $paid = invoice(['status' => 'paid']);
    DB::table('invoices')->whereIn('id', [$draft->id, $paid->id])->update(['amount' => '0.00']);

    $report = Sentinel::model(Invoice::class)->resealWhere(static fn (Builder $query) => $query->where('status', 'draft'), 'FIN-9 corrected', $admin, 'financial');

    expect($report->acknowledged)->toBe(1)
        ->and(Sentinel::verify($draft)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($paid)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::model(Invoice::class)->resealWhere(Invoice::query()->whereKey($draft->id), 'again')->skipped)->toBe(2)
        ->and(fn () => Sentinel::model(Invoice::class)->resealWhere(PlainRecord::query(), 'x'))->toThrow(SealingMisconfiguredException::class, 'not [')
        ->and(fn () => Sentinel::model(Invoice::class)->resealWhere(Invoice::query(), ' '))->toThrow(AcknowledgementDeniedException::class);

    config()->set('sentinel.acknowledgement.ability', 'acknowledge-tampering');
    Gate::define('acknowledge-tampering', static fn (): bool => false);

    expect(fn () => Sentinel::model(Invoice::class)->resealWhere(Invoice::query(), 'denied', $admin))->toThrow(AcknowledgementDeniedException::class);
});

it('mass-updates deliberately: verify all, update, re-seal with the reason (§10 item 15)', function (): void {
    $first = invoice(['status' => 'draft', 'currency' => 'USD']);
    $second = invoice(['status' => 'draft', 'currency' => 'USD']);
    $other = invoice(['status' => 'paid', 'currency' => 'USD']);

    $report = Sentinel::model(Invoice::class)->updateAndReseal(static fn (Builder $query) => $query->where('status', 'draft'), ['currency' => 'EUR'], 'FIN-12 currency migration', chunk: 1);

    $entry = LedgerEntry::query()->where('sealable_id', $first->id)->where('seal', 'financial')->orderByDesc('version')->firstOrFail();

    expect($report->resealed)->toBe(2)
        ->and(Invoice::query()->whereKey([$first->id, $second->id])->pluck('currency')->all())->toBe(['EUR', 'EUR'])
        ->and(Invoice::query()->whereKey($other->id)->value('currency'))->toBe('USD')
        ->and($entry->event)->toBe(SealEvent::Resealed)
        ->and($entry->reason)->toBe('FIN-12 currency migration')
        ->and(Sentinel::verifyMany([$first, $second, $other])->allIntact())->toBeTrue();
});

it('writes nothing when one selected row is not intact', function (): void {
    $intact = invoice(['status' => 'draft']);
    $tampered = invoice(['status' => 'draft']);
    DB::table('invoices')->where('id', $tampered->id)->update(['amount' => '0.00']);
    $before = LedgerEntry::query()->count();

    expect(fn () => Sentinel::model(Invoice::class)->updateAndReseal(Invoice::query()->where('status', 'draft'), ['currency' => 'GBP'], 'migration'))
        ->toThrow(TamperedModelException::class, '1 sealed model(s) are not intact');

    expect(Invoice::query()->whereKey($intact->id)->value('currency'))->toBe('EUR')
        ->and(LedgerEntry::query()->count())->toBe($before)
        ->and(fn () => Sentinel::model(Invoice::class)->updateAndReseal(Invoice::query(), ['bad column' => 1], 'x'))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::model(Invoice::class)->updateAndReseal(PlainRecord::query(), ['name' => 1], 'x'))->toThrow(SealingMisconfiguredException::class);
});

it('baselines rows that were never sealed, and only those', function (): void {
    $raw = Sentinel::withoutSealing(static fn (): Invoice => invoice(), 'import');
    $deleted = invoice();
    Seal::query()->where('sealable_id', $deleted->id)->where('seal', 'financial')->delete();
    $sealed = invoice();

    $report = Sentinel::model(Invoice::class)->sealMissing('Initial baseline', 'financial');

    expect($report->resealed)->toBe(1)
        ->and($report->skipped)->toBe(1)
        ->and($report->skippedResults[0]->reason)->toBe('seal_deleted')
        ->and(latestEvent($raw))->toBe(SealEvent::Baseline)
        ->and(Sentinel::verify($raw)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($deleted)->status)->toBe(VerificationStatus::Missing)
        ->and(Sentinel::model(Invoice::class)->sealMissing('again')->resealed)->toBe(1)
        ->and(Sentinel::verify($raw, 'identity')->status)->toBe(VerificationStatus::Intact)
        ->and([$sealed->id])->not->toBeEmpty()
        ->and(fn () => Sentinel::model(Invoice::class)->sealMissing(''))->toThrow(AcknowledgementDeniedException::class);
});

it('validates seal names on the bulk handle', function (): void {
    expect(fn () => Sentinel::model(Invoice::class)->scan('nope'))->toThrow(SealingMisconfiguredException::class)
        ->and(Sentinel::model(Invoice::class)->reseal('identity')->resealed)->toBe(0);
});
