<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Support\Forks;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Plan §12.5 items 5–7 on the real engines.
 */
it('lets concurrent checkpoint runs claim every entry exactly once', function (): void {
    foreach (range(1, 20) as $ignored) {
        invoice();
    }

    $outcomes = Forks::run(6, static function (): string {
        $made = 0;

        while (Sentinel::checkpoint(new CheckpointOptions(batchSize: 3)) !== null) {
            $made++;
        }

        return 'done';
    });

    $seqs = Checkpoint::query()->orderBy('seq')->pluck('seq')->all();

    expect($outcomes)->toBe(array_fill(0, 6, 'done'))
        ->and(LedgerEntry::query()->whereNull('checkpoint_id')->count())->toBe(0)
        ->and((int) Checkpoint::query()->sum('entries'))->toBe(40)
        ->and($seqs)->toBe(range(1, count($seqs)))
        ->and(Sentinel::verifyLedger()->clean())->toBeTrue();
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');

it('holds the model row lock for the whole sealed write', function (): void {
    $invoice = invoice();
    $outcome = null;

    $invoice->persistSealed(static function () use (&$outcome, $invoice): bool {
        // A second session cannot lock the row while the sealed write is in flight.
        $outcome = Forks::run(1, static function () use ($invoice): string {
            DB::statement(DriverMatrix::driver() === 'pgsql' ? "SET lock_timeout = '200ms'" : 'SET innodb_lock_wait_timeout = 1');

            try {
                DB::transaction(static fn () => DB::table('invoices')->where('id', $invoice->id)->lockForUpdate()->first());

                return 'locked';
            } catch (QueryException) {
                return 'timed out';
            }
        })[0];

        return true;
    });

    expect($outcome)->toBe('timed out');
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');

it('verifies the row as it is, not an older snapshot, before a write', function (): void {
    $invoice = invoice(['amount' => '1.00']);

    DB::beginTransaction();

    try {
        // A plain read first: on MySQL REPEATABLE READ it pins this transaction's snapshot.
        DB::table('invoices')->where('id', $invoice->id)->first();

        $outcome = Forks::run(1, static function () use ($invoice): string {
            DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

            return 'tampered';
        })[0];

        expect($outcome)->toBe('tampered')
            ->and(fn () => $invoice->update(['note' => 'after the out-of-band change']))->toThrow(TamperedModelException::class);
    } finally {
        DB::rollBack();
    }
})->skip(fn (): bool => ! Forks::available(), 'needs a real engine (pgsql or mysql) and pcntl + posix');
