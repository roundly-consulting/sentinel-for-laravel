<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Real concurrency on a real engine (plan §12.5 items 1–2): eight forked processes, each with
 * its own session, write the same sealed model at once. The row lock taken before the write
 * serialises them; versions stay contiguous and the final seal is intact. SQLite serialises
 * whole-database writes, so these run on the pgsql and mysql legs only.
 *
 * @param  Closure(Invoice): mixed  $operation
 * @return list<string>
 */
function raceSealing(int $id, Closure $operation, int $racers = 8): array
{
    $files = [];
    $pids = [];

    for ($i = 0; $i < $racers; $i++) {
        $file = (string) tempnam(sys_get_temp_dir(), 'sentinel-race-');
        $pid = pcntl_fork();

        if ($pid === 0) {
            $outcome = 'error';

            try {
                // A separate session; never touch the parent's connection.
                config()->set('database.connections.racer', DriverMatrix::connectionConfig(DriverMatrix::driver()));
                DB::setDefaultConnection('racer');
                app()->forgetScopedInstances();

                $operation(Invoice::on('racer')->findOrFail($id));
                $outcome = 'done';
            } catch (Throwable $exception) {
                $outcome = 'error: '.$exception::class.': '.$exception->getMessage();
            }

            file_put_contents($file, $outcome);

            // No shutdown handlers, no destructors, no test teardown in the child.
            posix_kill(posix_getpid(), SIGKILL);
        }

        $files[] = $file;
        $pids[] = $pid;
    }

    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }

    $outcomes = array_map(static fn (string $file): string => (string) file_get_contents($file), $files);
    array_map(unlink(...), $files);

    return $outcomes;
}

function realEngineUnavailable(): bool
{
    return DriverMatrix::driver() === 'sqlite' || ! function_exists('pcntl_fork') || ! function_exists('posix_kill');
}

it('serialises eight concurrent sealed writes of one model', function (): void {
    $invoice = invoice(['customer_id' => 0]);

    $outcomes = raceSealing($invoice->id, static fn (Invoice $racer) => $racer->increment('customer_id'));

    $versions = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->orderBy('version')->pluck('version')->all();

    expect($outcomes)->toBe(array_fill(0, 8, 'done'))
        ->and($versions)->toBe(range(1, 9))
        ->and((int) DB::table('invoices')->where('id', $invoice->id)->value('customer_id'))->toBe(8)
        ->and(Sentinel::verify($invoice->fresh() ?? $invoice)->status)->toBe(VerificationStatus::Intact);
})->skip(fn (): bool => realEngineUnavailable(), 'needs a real engine (pgsql or mysql) and pcntl + posix');

it('lets exactly one racer create the first seal of a never-sealed model', function (): void {
    config()->set('sentinel.sealing.allow_suspension', true);
    $invoice = Sentinel::withoutSealing(static fn (): Invoice => invoice(), 'race setup');

    $outcomes = raceSealing($invoice->id, static fn (Invoice $racer) => Sentinel::seal($racer));

    $events = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->orderBy('version')
        ->get()->map(static fn (LedgerEntry $entry): string => $entry->event->value)->all();

    expect($outcomes)->toBe(array_fill(0, 8, 'done'))
        ->and($events[0])->toBe(SealEvent::Sealed->value)
        ->and(array_count_values($events))->toBe(['sealed' => 1, 'resealed' => 7])
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);
})->skip(fn (): bool => realEngineUnavailable(), 'needs a real engine (pgsql or mysql) and pcntl + posix');
