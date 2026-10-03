<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIsAppendOnlyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * §10 item 36: every audit field of a ledger entry is covered by the entry's own MAC.
 */
it('covers every audit column with the entry MAC', function (string $column, mixed $value): void {
    $invoice = invoice();
    Sentinel::acknowledge($invoice, 'nothing changed', seal: 'identity');
    $entry = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->firstOrFail();

    LedgerEntry::query()->whereKey($entry->id)->toBase()->update([$column => $value]);

    $kinds = array_map(static fn (LedgerFinding $finding): string => $finding->kind->value, Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false))->findings);

    expect($kinds)->toContain('entry_invalid');
})->with([
    ['sealable_type', 'other'],
    ['sealable_id', 999],
    ['seal', 'identity2'],
    ['event', 'resealed'],
    ['version', 7],
    ['key_id', 'other'],
    ['algorithm', 'hmac-sha512'],
    ['seal_mac', 'AAAA'],
    ['previous_digest', 'prev'],
    ['changed', '["a:amount"]'],
    ['previous_status', 'tampered'],
    ['actor_type', 'users'],
    ['actor_id', 5],
    ['reason', 'edited later'],
    ['entry_mac', 'AAAA'],
    ['occurred_at', '2020-01-01 00:00:00.000000'],
]);

it('only trusts an entry vouched for by a ring its seal accepts', function (): void {
    // The same root secret, registered as a partner key in the http ring.
    Key::factory()->ring('http')->create(['kid' => TestCase::ROOT_KEY_ID]);
    $invoice = invoice();
    LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->toBase()->update(['ring' => 'http']);

    $result = Sentinel::verify($invoice);

    expect($result->status)->toBe(VerificationStatus::Tampered)
        ->and($result->reason)->toBe('ledger_entry');
});

it('refuses Eloquent updates and deletes of ledger rows with model events muted (dual-review O-37)', function (): void {
    invoice();
    Sentinel::checkpoint();
    $entry = LedgerEntry::query()->firstOrFail();
    $checkpoint = Checkpoint::query()->firstOrFail();

    expect(fn () => $entry->updateQuietly(['reason' => 'rewritten']))->toThrow(LedgerIsAppendOnlyException::class, 'cannot be updated')
        ->and(fn () => LedgerEntry::withoutEvents(static fn () => $entry->forceFill(['reason' => 'x'])->save()))->toThrow(LedgerIsAppendOnlyException::class)
        ->and(fn () => $entry->deleteQuietly())->toThrow(LedgerIsAppendOnlyException::class, 'cannot be deleted')
        ->and(fn () => $checkpoint->updateQuietly(['root' => 'x']))->toThrow(LedgerIsAppendOnlyException::class, 'cannot be updated')
        ->and(fn () => $checkpoint->deleteQuietly())->toThrow(LedgerIsAppendOnlyException::class, 'cannot be deleted')
        ->and(LedgerEntry::query()->whereKey($entry->id)->value('reason'))->not->toBe('rewritten');
});

it('binds the context into the whole ledger: it is set once, for the ledger\'s lifetime (dual-review O-36)', function (): void {
    $invoice = invoice();
    Sentinel::checkpoint();
    config()->set('sentinel.context', 'renamed-app');

    // Seals can be re-adopted under a new context …
    expect(Artisan::call('sentinel:reseal', ['model' => Invoice::class, '--acknowledge' => 'context change']))->toBe(0)
        ->and(Sentinel::verify($invoice)->isIntact())->toBeTrue();

    // … but the ledger written under the old one never verifies again (documented: the
    // context is permanent for a ledger's lifetime).
    $kinds = array_values(array_unique(array_map(static fn (LedgerFinding $finding): string => $finding->kind->value, Sentinel::verifyLedger()->violations())));

    expect($kinds)->toContain('entry_invalid')->toContain('checkpoint_invalid');
});
