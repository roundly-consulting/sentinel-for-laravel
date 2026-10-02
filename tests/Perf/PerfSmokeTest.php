<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Sealable;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

/**
 * Performance smoke (plan §11 Phase H, I-5): seal 1 000 rows through Eloquent and verify them with
 * the chunked scan, per algorithm, on in-memory SQLite. Printed, never asserted — excluded
 * from the default run; `composer perf` runs it. Numbers are in the technical docs.
 */
const PERF_ROWS = 1000;

it('seals and verifies 1 000 rows', function (Algorithm $algorithm): void {
    config()->set('sentinel.keys.rings.default.driver', 'database');
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring()->generate($algorithm);

    $started = hrtime(true);

    for ($i = 0; $i < PERF_ROWS; $i++) {
        PlainRecord::query()->create(['name' => "row {$i}", 'count' => $i, 'code' => 'P', 'flag' => $i % 2 === 0]);
    }

    $sealed = (hrtime(true) - $started) / 1e6;
    $started = hrtime(true);
    $report = Sentinel::model(PlainRecord::class)->scan();
    $verified = (hrtime(true) - $started) / 1e6;

    fwrite(STDERR, sprintf(
        "\n  %-18s seal %6.0f ms (%.2f ms/row)   verify %6.0f ms (%.2f ms/row)   intact %d/%d",
        $algorithm->value, $sealed, $sealed / PERF_ROWS, $verified, $verified / PERF_ROWS, $report->scanned, PERF_ROWS,
    ));

    expect($report->scanned)->toBe(PERF_ROWS)
        ->and($report->hasFindings())->toBeFalse();
})->with(Algorithm::cases())->group('perf');

const PERF_RETRIEVE_ROWS = 5000;

/**
 * I-5: reading sealable models costs nothing extra unless a seal verifies on retrieve.
 * Best of three `get()` runs over the same 5 000 rows of one table.
 */
it('retrieves 5 000 rows: plain, sealable, sealable with a retrieve seal', function (): void {
    $suffix = bin2hex(random_bytes(4));
    eval('final class PerfPlain'.$suffix.' extends '.Model::class.' { protected $table = "plain_records"; protected $guarded = []; }');
    eval('final class PerfGuarded'.$suffix.' extends '.Model::class.' implements '.Sealable::class.' {
        use '.HasSeals::class.';
        protected $table = "plain_records";
        protected $guarded = [];
        public static function defineSeals('.SealBuilder::class.' $seals): void { $seals->seal("default")->attributes("name", "count")->verifyOnRetrieve(); }
    }');
    $plain = 'PerfPlain'.$suffix;
    $guarded = 'PerfGuarded'.$suffix;

    for ($i = 0; $i < PERF_RETRIEVE_ROWS; $i++) {
        $guarded::query()->create(['name' => "row {$i}", 'count' => $i]);
    }

    $best = static function (Closure $read): float {
        $times = [];

        for ($run = 0; $run < 3; $run++) {
            $started = hrtime(true);
            expect($read())->toHaveCount(PERF_RETRIEVE_ROWS);
            $times[] = (hrtime(true) - $started) / 1e6;
        }

        return min($times);
    };

    $plainMs = $best(static fn () => $plain::query()->get());
    $sealableMs = $best(static fn () => PlainRecord::query()->get());
    $guardedMs = $best(static fn () => $guarded::query()->get());

    fwrite(STDERR, sprintf(
        "\n  retrieve %d rows   plain %5.0f ms   sealable %5.0f ms (%.2f×)   retrieve seal %5.0f ms (%.2f×)",
        PERF_RETRIEVE_ROWS, $plainMs, $sealableMs, $sealableMs / $plainMs, $guardedMs, $guardedMs / $plainMs,
    ));
})->group('perf');
