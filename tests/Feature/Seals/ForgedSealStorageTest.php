<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

/**
 * The seal row's `manifest`, `field_tags` and `attributes_mac` columns and the ledger head are
 * written by whoever can write the database (threat-model A1). Nothing stored there may turn a
 * failure into "intact", "computed-only drift", "deleted" or "skip".
 */

/**
 * A1: change a sealed column, drop it from the seal row's manifest and field tags, and plant a
 * computed tag — forged "computed-only drift".
 */
function forgeComputedOnlyDrift(string $table, int|string $id, string $seal, string $column, mixed $value, string $planted = 'c:x'): void
{
    DB::table($table)->where('id', $id)->update([$column => $value]);

    $row = DB::table('sentinel_seals')->where('sealable_id', $id)->where('seal', $seal)->first();
    $manifest = array_values(array_filter(json_decode((string) $row->manifest, true), static fn (array $pair): bool => $pair[0] !== "a:{$column}"));
    $tags = json_decode((string) ($row->field_tags ?? '{}'), true);
    unset($tags["a:{$column}"]);
    $tags[$planted] = 'AAAAAAAAAAAAAAAAAAAAAA';

    DB::table('sentinel_seals')->where('id', $row->id)->update(['manifest' => json_encode($manifest), 'field_tags' => json_encode($tags)]);
}

it('never reads forged field tags as computed-only drift (dual-review O-1)', function (): void {
    $record = record(['count' => 3]);
    forgeComputedOnlyDrift('plain_records', $record->id, 'default', 'count', 999);

    $verdict = Sentinel::verify($record);

    expect($verdict->status)->toBe(VerificationStatus::Tampered)
        ->and($verdict->reason)->toBe('mac')
        ->and($verdict->onlyComputedChanged())->toBeFalse();
});

it('refuses an ordinary save over forged computed-only drift and leaves the row tampered (dual-review O-1)', function (): void {
    $record = record(['count' => 3]);
    forgeComputedOnlyDrift('plain_records', $record->id, 'default', 'count', 999);

    $fresh = PlainRecord::query()->findOrFail($record->id);
    $fresh->name = 'beta';

    expect(fn () => $fresh->save())->toThrow(TamperedModelException::class)
        ->and(PlainRecord::query()->findOrFail($record->id)->count)->toBe(999)
        ->and(Sentinel::verify(PlainRecord::query()->findOrFail($record->id))->status)->toBe(VerificationStatus::Tampered);
});

it('refuses an explicit seal() of forged computed-only drift (dual-review O-1)', function (): void {
    $record = record(['count' => 3]);
    forgeComputedOnlyDrift('plain_records', $record->id, 'default', 'count', 999);

    expect(fn () => Sentinel::seal(PlainRecord::query()->findOrFail($record->id)))->toThrow(TamperedModelException::class, 'tampered: mac');
});

it('refuses forged drift on a seal that declares computed fields, on every write path (dual-review F-1)', function (): void {
    $invoice = invoice(['amount' => '10.50']);
    forgeComputedOnlyDrift('invoices', $invoice->id, 'financial', 'amount', '99999.00', 'c:ghost');

    expect(Sentinel::verify($invoice)->onlyComputedChanged())->toBeFalse()
        ->and(fn () => Invoice::query()->findOrFail($invoice->id)->update(['note' => 'routine edit']))->toThrow(TamperedModelException::class)
        ->and(fn () => Sentinel::seal(Invoice::query()->findOrFail($invoice->id)))->toThrow(TamperedModelException::class);

    // A soft delete never re-seals a non-benign row either.
    Invoice::query()->findOrFail($invoice->id)->delete();

    expect(Sentinel::verify(Invoice::withTrashed()->findOrFail($invoice->id))->status)->toBe(VerificationStatus::Tampered)
        ->and(LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->where('previous_status', 'tampered')->exists())->toBeFalse();
});

it('refuses forged drift on a fieldTags(false) seal whose manifest was reduced to its computed fields (dual-review O-1)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('nt')->attributes('number', 'amount')
        ->computed('one', static fn ($m): int => 1)->fieldTags(false));
    $model = $class::query()->create(['number' => 'n-1', 'amount' => '5.00']);
    $row = DB::table('sentinel_seals')->where('sealable_id', $model->getKey())->where('seal', 'nt')->first();

    DB::table('invoices')->where('id', $model->getKey())->update(['amount' => '0.01']);
    DB::table('sentinel_seals')->where('id', $row->id)->update([
        'manifest' => json_encode([['c:one', 'auto']]),
        'field_tags' => json_encode(['c:x' => 'AAAAAAAAAAAAAAAAAAAAAA']),
    ]);

    $fresh = $class::query()->findOrFail($model->getKey());
    $fresh->number = 'n-2';

    expect(Sentinel::verify($model)->onlyComputedChanged())->toBeFalse()
        ->and(fn () => $fresh->save())->toThrow(TamperedModelException::class)
        ->and(Sentinel::verify($class::query()->findOrFail($model->getKey()))->status)->toBe(VerificationStatus::Tampered);
});

it('still re-seals genuine computed drift — proven by the attributes MAC, not the tags (dual-review O-1)', function (): void {
    $invoice = invoice();
    DB::table('invoice_lines')->insert(['invoice_id' => $invoice->id, 'sku' => 'B-2', 'quantity' => 3]);

    $drift = Sentinel::verify($invoice);

    expect($drift->status)->toBe(VerificationStatus::Tampered)
        ->and($drift->reason)->toBe('computed')
        ->and($drift->onlyComputedChanged())->toBeTrue()
        ->and($drift->changedAttributes)->toBe(['c:lines']);

    // Forged tags naming an attribute never make genuine drift look like more (or less).
    $row = DB::table('sentinel_seals')->where('sealable_id', $invoice->id)->where('seal', 'financial')->first();
    $tags = json_decode((string) $row->field_tags, true);
    $tags['a:amount'] = 'AAAAAAAAAAAAAAAAAAAAAA';
    DB::table('sentinel_seals')->where('id', $row->id)->update(['field_tags' => json_encode($tags)]);

    expect(Sentinel::verify($invoice)->changedAttributes)->toBe(['c:lines']);

    $invoice->update(['note' => 'touched']);

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);
});

it('re-seals computed drift without field tags and on asymmetric keys (dual-review O-1)', function (): void {
    config()->set('sentinel.keys.rings.default.key_id', 'ed');
    config()->set('sentinel.keys.rings.default.key', KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate());
    config()->set('sentinel.keys.rings.default.algorithm', 'ed25519');
    app(KeyStoreManager::class)->flush();
    $invoice = invoice();
    DB::table('invoice_lines')->insert(['invoice_id' => $invoice->id, 'sku' => 'B-2', 'quantity' => 3]);

    $drift = Sentinel::verify($invoice);

    expect($drift->reason)->toBe('computed')
        ->and($drift->changedAttributes)->toBeNull()
        ->and(Sentinel::seal($invoice)->version)->toBe(2)
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);
});

it('refuses computed drift whose attributes MAC was removed or replayed (dual-review O-1)', function (): void {
    $invoice = invoice();
    $old = DB::table('sentinel_seals')->where('sealable_id', $invoice->id)->where('seal', 'financial')->first();

    // A rolled-back row plus its old seal row, then drift: the ledger still sees the rollback.
    $invoice->update(['amount' => '20.00']);
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '10.50']);
    DB::table('sentinel_seals')->where('id', $old->id)->update((array) $old);
    DB::table('invoice_lines')->insert(['invoice_id' => $invoice->id, 'sku' => 'B-2', 'quantity' => 3]);

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Stale)
        ->and(fn () => Invoice::query()->findOrFail($invoice->id)->update(['note' => 'x']))->toThrow(TamperedModelException::class);

    $other = invoice();
    DB::table('invoice_lines')->insert(['invoice_id' => $other->id, 'sku' => 'C-3', 'quantity' => 1]);
    DB::table('sentinel_seals')->where('sealable_id', $other->id)->where('seal', 'financial')->update(['attributes_mac' => null]);

    expect(Sentinel::verify($other)->reason)->toBe('mac')
        ->and(fn () => Sentinel::seal($other))->toThrow(TamperedModelException::class);

    DB::table('sentinel_seals')->where('sealable_id', $other->id)->where('seal', 'financial')->update(['attributes_mac' => '!not base64url!']);

    expect(Sentinel::verify($other)->reason)->toBe('mac');
});

/**
 * A1: append a manifest entry for a column the table does not have (or one the seal does not
 * cover) to a tampered row's seal.
 */
function poisonManifest(int|string $id, string $seal, string $column = 'zzz'): void
{
    $row = DB::table('sentinel_seals')->where('sealable_id', $id)->where('seal', $seal)->first();
    $manifest = json_decode((string) $row->manifest, true);
    $manifest[] = ["a:{$column}", 'str'];
    DB::table('sentinel_seals')->where('id', $row->id)->update(['manifest' => json_encode($manifest)]);
}

it('refuses to load a tampered row whose manifest names a column that does not exist (dual-review O-2)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount')->verifyOnRetrieve(Reaction::Throw));
    $model = $class::query()->create(['number' => 'r-1', 'amount' => '5.00']);

    DB::table('invoices')->where('id', $model->getKey())->update(['amount' => '0.00']);
    poisonManifest($model->getKey(), 'guarded');

    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class, 'malformed: manifest')
        ->and(Sentinel::verify($model)->status)->toBe(VerificationStatus::Malformed)
        ->and(Sentinel::verify($model)->reason)->toBe('manifest');
});

it('reads a manifest column the seal no longer covers instead of skipping it as a partial select (dual-review O-2)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount')->verifyOnRetrieve(Reaction::Throw));
    $model = $class::query()->create(['number' => 'r-2', 'amount' => '5.00']);
    DB::table('invoices')->where('id', $model->getKey())->update(['amount' => '0.00']);
    poisonManifest($model->getKey(), 'guarded', 'note');

    // Every sealed column is selected: the row is verified (and refused), never skipped.
    expect(fn () => $class::query()->select('id', 'number', 'amount')->find($model->getKey()))->toThrow(TamperedModelException::class, 'tampered: mac')
        // A partial select of the seal's own columns stays unverifiable, as documented.
        ->and($class::query()->select('id', 'number')->find($model->getKey())?->getKey())->toBe($model->getKey());
});

it('returns a status for a poisoned manifest on every engine and every path (dual-review O-2)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount'));
    $model = $class::query()->create(['number' => 'r-3', 'amount' => '5.00']);
    poisonManifest($model->getKey(), 'guarded');

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Malformed)
        ->and(fn () => $class::query()->findOrFail($model->getKey())->update(['number' => 'x']))->toThrow(TamperedModelException::class, 'malformed: manifest')
        ->and(Sentinel::acknowledge($model, 'INC-7: manifest repaired')->acknowledged)->toBeTrue()
        ->and(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact);
});

it('keeps scanning past a poisoned row and reports the other tampered rows (dual-review O-2)', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount'));
    $a = $class::query()->create(['number' => 'a', 'amount' => '5.00']);
    $b = $class::query()->create(['number' => 'b', 'amount' => '5.00']);
    DB::table('invoices')->where('id', $b->getKey())->update(['amount' => '0.00']);
    poisonManifest($a->getKey(), 'guarded');

    $report = Sentinel::scan(new ScanOptions([$class]));

    expect(array_map(static fn ($result): string => $result->status->value.':'.$result->reason, $report->findings))->toBe(['malformed:manifest', 'tampered:mac']);
});

it('reports a row whose verification throws as a finding and keeps scanning (dual-review O-2)', function (): void {
    Event::fake([TamperDetected::class]);
    $class = definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount')
        ->computed('checked', static fn ($m): string => $m->number === 'boom' ? throw new RuntimeException('host closure failed') : 'ok'));
    $a = $class::query()->create(['number' => 'a', 'amount' => '5.00']);
    $b = $class::query()->create(['number' => 'b', 'amount' => '5.00']);
    DB::table('invoices')->where('id', $a->getKey())->update(['number' => 'boom']);
    DB::table('invoices')->where('id', $b->getKey())->update(['amount' => '0.00']);

    $report = Sentinel::scan(new ScanOptions([$class]));

    expect(array_map(static fn ($result): string => $result->status->value.':'.$result->reason, $report->findings))->toBe(['unverifiable:error', 'tampered:mac'])
        ->and($report->scanned)->toBe(2);

    Event::assertDispatched(TamperDetected::class, static fn (TamperDetected $event): bool => $event->reason === 'error');
});

it('still verifies an outdated row whose manifest names a column the definition dropped', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount', 'note')->verifyOnRetrieve(Reaction::Throw));
    $model = $class::query()->create(['number' => 'o-1', 'amount' => '5.00', 'note' => 'n']);
    $class::$define = static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount')->verifyOnRetrieve(Reaction::Throw);
    app()->forgetInstance(DefinitionRegistry::class);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Outdated)
        ->and($class::query()->select('id', 'number', 'amount')->find($model->getKey())?->getKey())->toBe($model->getKey());

    DB::table('invoices')->where('id', $model->getKey())->update(['note' => 'changed']);

    expect(fn () => $class::query()->select('id', 'number', 'amount')->find($model->getKey()))->toThrow(TamperedModelException::class, 'tampered: mac');
});

/**
 * A1: delete the seal row and append a ledger row closing the history — with no valid MAC.
 */
function forgeTombstone(Model $model, string $seal, string $event = 'unsealed'): void
{
    $head = DB::table('sentinel_ledger')->where('sealable_id', $model->getKey())->where('seal', $seal)->orderByDesc('version')->first();
    DB::table('sentinel_seals')->where('sealable_id', $model->getKey())->where('seal', $seal)->delete();
    DB::table('sentinel_ledger')->insert([
        'sealable_type' => $model->getMorphClass(), 'sealable_id' => $model->getKey(), 'seal' => $seal, 'event' => $event,
        'version' => $head->version + 1, 'ring' => $head->ring, 'key_id' => $head->key_id, 'algorithm' => $head->algorithm,
        'reason' => 'x', 'entry_mac' => 'AAAA', 'occurred_at' => '2026-10-03 00:00:00.000000',
    ]);
}

it('never reads a forged tombstone as a lenient seal\'s legitimate end (dual-review O-4)', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['number' => 'FORGED']);
    forgeTombstone($invoice, 'identity');

    $verdict = Sentinel::verify($invoice, 'identity');

    expect($verdict->status)->toBe(VerificationStatus::Tampered)
        ->and($verdict->reason)->toBe('ledger_entry')
        ->and($verdict->isIntact())->toBeFalse()
        ->and(fn () => Invoice::query()->findOrFail($invoice->id)->update(['number' => 'again']))->toThrow(TamperedModelException::class, 'tampered: ledger_entry');
});

it('never lets seal() re-seal a strict model behind a forged unsealed tombstone (dual-review O-4)', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);
    forgeTombstone($invoice, 'financial');

    expect(Sentinel::verify($invoice, 'financial')->reason)->toBe('ledger_entry')
        ->and(fn () => Sentinel::seal(Invoice::query()->findOrFail($invoice->id), 'financial'))->toThrow(TamperedModelException::class, 'ledger_entry');
});

it('treats a re-used id behind a forged deleted tombstone as recreated (dual-review O-4)', function (): void {
    $invoice = invoice();
    $id = $invoice->id;
    forgeTombstone($invoice, 'financial', 'deleted');
    forgeTombstone($invoice, 'identity', 'deleted');
    DB::table('invoices')->where('id', $id)->delete();

    expect(fn () => invoice(['id' => $id]))->toThrow(TamperedModelException::class, 'stale: entity_recreated')
        ->and(DB::table('invoices')->where('id', $id)->exists())->toBeFalse();
});

it('still honours a genuine tombstone (dual-review O-4)', function (): void {
    $invoice = invoice();
    Sentinel::unseal($invoice, 'INC-9: re-imported', seal: 'identity');
    Sentinel::unseal($invoice, 'INC-9: re-imported', seal: 'financial');

    expect(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Unsealed)
        ->and(Sentinel::verify($invoice, 'financial')->reason)->toBe('unsealed');

    $id = $invoice->id;
    $invoice->forceDelete();

    expect(Sentinel::verify(invoice(['id' => $id]))->status)->toBe(VerificationStatus::Intact);
});
