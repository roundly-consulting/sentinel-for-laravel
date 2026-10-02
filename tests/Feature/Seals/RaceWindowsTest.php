<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Exceptions\ConcurrentSealException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Check-then-act windows (fleet theme 2). The real-engine legs race these with forked
 * processes; here each window is opened deterministically on the one connection, so the
 * guard that closes it runs on every leg's coverage.
 */
function onFirstTransaction(Closure $interfere): void
{
    $done = false;

    Event::listen(TransactionBeginning::class, static function () use ($interfere, &$done): void {
        if (! $done) {
            $done = true;
            $interfere();
        }
    });
}

function afterTailRead(Closure $interfere, bool $always = false): void
{
    $done = false;

    DB::listen(static function (QueryExecuted $query) use ($interfere, $always, &$done): void {
        if ((! $done || $always) && DB::transactionLevel() > 0 && str_contains($query->sql, 'from "sentinel_checkpoints" order by "seq" desc')) {
            $done = true;
            $interfere();
        }
    });
}

function forgedCheckpoint(int $seq): void
{
    DB::table('sentinel_checkpoints')->insert([
        'seq' => $seq, 'first_entry_id' => 0, 'last_entry_id' => 0, 'entries' => 0, 'root' => 'forged-root', 'ring' => 'default',
        'key_id' => 'forged', 'algorithm' => 'hmac-sha256', 'mac' => 'forged', 'created_at' => '2026-01-01 00:00:00.000000',
    ]);
}

it('refuses to seal, unseal or acknowledge a model whose row has vanished', function (Closure $operation): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->delete();

    expect(fn () => $operation($invoice))->toThrow(SealingFailedException::class, 'disappeared between the write and the read-back');
})->with([
    'seal' => [static fn (Invoice $invoice) => Sentinel::seal($invoice)],
    'unseal' => [static fn (Invoice $invoice) => Sentinel::unseal($invoice, 'archived')],
    'acknowledge' => [static fn (Invoice $invoice) => Sentinel::acknowledge($invoice, 'fixed by the DBA')],
]);

it('refuses a mass update when a row is tampered between the read-only pass and the locked pass', function (): void {
    $invoice = invoice();
    onFirstTransaction(static fn () => DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']));

    expect(fn () => Sentinel::model(Invoice::class)->updateAndReseal(fn ($query) => $query->whereKey($invoice->id), ['note' => 'bulk'], 'FIN-12'))
        ->toThrow(TamperedModelException::class, '1 sealed model(s) are not intact; nothing was written.')
        ->and(DB::table('invoices')->where('id', $invoice->id)->value('note'))->toBeNull();
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

it('skips a row deleted between the read-only pass and the locked pass', function (): void {
    $invoice = invoice();
    onFirstTransaction(static fn () => DB::table('invoices')->where('id', $invoice->id)->delete());

    $report = Sentinel::model(Invoice::class)->updateAndReseal(fn ($query) => $query->whereKey($invoice->id), ['note' => 'bulk'], 'FIN-12');

    expect($report->resealed)->toBe(0)
        ->and(Invoice::withTrashed()->whereKey($invoice->id)->exists())->toBeFalse();
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

it('rolls back a host write that removed its own row before the seal could read it back', function (): void {
    $invoice = invoice();
    $versions = LedgerEntry::query()->count();

    expect(fn () => $invoice->persistSealed(static fn (): int => DB::table('invoices')->where('id', $invoice->id)->delete()))
        ->toThrow(SealingFailedException::class, 'disappeared between the write and the read-back')
        ->and(Invoice::query()->whereKey($invoice->id)->exists())->toBeTrue()
        ->and(LedgerEntry::query()->count())->toBe($versions)
        ->and(Sentinel::verify($invoice)->isIntact())->toBeTrue();
});

it('fails loudly when a host write claims success without persisting the model', function (): void {
    $record = new PlainRecord(['name' => 'ghost']);

    expect(fn () => $record->persistSealed(static fn (): bool => true))
        ->toThrow(SealingFailedException::class, 'must be persisted before it can be sealed')
        ->and(LedgerEntry::query()->count())->toBe(0);
});

it('writes nothing when a listener cancels the save of a sealed model', function (): void {
    $invoice = invoice();
    $versions = LedgerEntry::query()->count();
    Invoice::saving(static fn (): bool => false);

    expect($invoice->update(['amount' => '99.00']))->toBeFalse()
        ->and(LedgerEntry::query()->count())->toBe($versions)
        ->and((float) DB::table('invoices')->where('id', $invoice->id)->value('amount'))->toBe(10.5)
        ->and(Sentinel::verify($invoice->refresh())->isIntact())->toBeTrue();
});

it('chains onto the true checkpoint tail when another run commits one between two reads', function (): void {
    invoice();
    afterTailRead(static fn () => forgedCheckpoint(1));

    expect(Sentinel::checkpoint()?->seq)->toBe(2)
        ->and(Checkpoint::query()->orderBy('seq')->pluck('seq')->all())->toBe([1, 2])
        // The intruder could not produce a valid MAC: the ledger check says so.
        ->and(array_map(static fn ($finding) => $finding->kind, Sentinel::verifyLedger()->findings))->toContain(LedgerFindingKind::CheckpointInvalid);
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

it('gives up when the checkpoint tail never holds still', function (): void {
    invoice();
    $seq = 0;
    afterTailRead(static function () use (&$seq): void {
        forgedCheckpoint(++$seq);
    }, always: true);

    expect(fn () => Sentinel::checkpoint())->toThrow(ConcurrentSealException::class, 'Another checkpoint run raced')
        ->and(Checkpoint::query()->count())->toBe(0);
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');
