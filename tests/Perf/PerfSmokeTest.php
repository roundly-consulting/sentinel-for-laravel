<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

/**
 * Performance smoke (plan §11 Phase H): seal 1 000 rows through Eloquent and verify them with
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
