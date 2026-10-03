<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\SchemaColumns;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

/**
 * Rows sealed under an older, wider definition carry a manifest naming a column the current
 * seal no longer covers. The verifier checks that column against the schema, and the listing
 * is memoised per (connection, table) for the request or job only, never per row and never
 * process-wide.
 */

/**
 * How many column listings of `$table` the callback reads, recognised by the exact SQL the
 * connection issues first for that listing on the current engine (SQLite follows it with a
 * `sqlite_master` read, which is counted once with it).
 */
function columnListingQueries(string $table, Closure $callback): int
{
    DB::flushQueryLog();
    DB::enableQueryLog();
    Schema::getColumnListing($table);
    $listing = DB::getQueryLog()[0]['query'];
    DB::flushQueryLog();

    try {
        $callback();

        return count(array_filter(DB::getQueryLog(), static fn (array $query): bool => $query['query'] === $listing));
    } finally {
        DB::disableQueryLog();
        DB::flushQueryLog();
    }
}

/**
 * Seal rows under (number, amount, note), then drop `note` from the definition, so every
 * stored manifest names a column outside the current seal.
 *
 * @return array{0: class-string<Model>, 1: list<int|string>}
 */
function rowsSealedUnderAWiderDefinition(int $rows, bool $verifyOnRetrieve = false): array
{
    $define = static fn (array $columns) => static function ($seals) use ($columns, $verifyOnRetrieve): void {
        $seal = $seals->seal('guarded')->attributes(...$columns);
        $verifyOnRetrieve && $seal->verifyOnRetrieve(Reaction::Throw);
    };
    $class = definedBy($define(['number', 'amount', 'note']));
    $ids = [];

    for ($i = 0; $i < $rows; $i++) {
        $ids[] = $class::query()->create(['number' => "w-{$i}", 'amount' => '5.00', 'note' => 'n'])->getKey();
    }

    $class::$define = $define(['number', 'amount']);
    app()->forgetInstance(DefinitionRegistry::class);
    app()->forgetScopedInstances();

    return [$class, $ids];
}

it('checks an older manifest against the schema once per request, not once per verified row (dual-review FR-1)', function (): void {
    [$class, $ids] = rowsSealedUnderAWiderDefinition(5);
    $statuses = [];

    $queries = columnListingQueries('invoices', function () use ($class, $ids, &$statuses): void {
        foreach ($ids as $id) {
            $statuses[] = Sentinel::verify($class::query()->findOrFail($id))->status;
        }
    });

    expect($queries)->toBe(1)
        ->and($statuses)->toBe(array_fill(0, 5, VerificationStatus::Outdated));
});

it('keeps verify-on-retrieve and scans at one schema query whatever the row count (dual-review FR-1)', function (): void {
    [$class, $ids] = rowsSealedUnderAWiderDefinition(5, verifyOnRetrieve: true);

    expect(columnListingQueries('invoices', fn () => expect($class::query()->get())->toHaveCount(5)))->toBe(1);

    app()->forgetScopedInstances();
    $report = null;

    expect(columnListingQueries('invoices', function () use ($class, &$report): void {
        $report = Sentinel::scan(new ScanOptions([$class]));
    }))->toBe(1)
        ->and($report?->scanned)->toBe(5);
});

it('still refuses an edited-in column when the listing comes from the memo (dual-review FR-1)', function (): void {
    [$class, $ids] = rowsSealedUnderAWiderDefinition(3);
    foreach ([$ids[1], $ids[2]] as $id) {
        $row = DB::table('sentinel_seals')->where('sealable_id', $id)->where('seal', 'guarded')->first();
        DB::table('sentinel_seals')->where('id', $row->id)->update(['manifest' => json_encode([...json_decode((string) $row->manifest, true), ['a:zzz', 'str']])]);
    }
    $results = [];

    $queries = columnListingQueries('invoices', function () use ($class, $ids, &$results): void {
        foreach ($ids as $id) {
            $result = Sentinel::verify($class::query()->findOrFail($id));
            $results[] = $result->status->value.':'.$result->reason;
        }
    });

    expect($queries)->toBe(1)
        ->and($results)->toBe(['outdated:', 'malformed:manifest', 'malformed:manifest']);
});

it('memoises the listing for one request or job only, never across Octane requests (dual-review FR-1)', function (): void {
    [$class, $ids] = rowsSealedUnderAWiderDefinition(1);
    $model = $class::query()->findOrFail($ids[0]);
    $memo = app(SchemaColumns::class);

    expect(columnListingQueries('invoices', function () use ($model): void {
        Sentinel::verify($model);
        Sentinel::verify($model);
    }))->toBe(1)
        ->and(app(SchemaColumns::class))->toBe($memo);

    // What Octane and the queue worker do between units of work.
    app()->forgetScopedInstances();

    expect(app(SchemaColumns::class))->not->toBe($memo)
        ->and(columnListingQueries('invoices', fn () => Sentinel::verify($model)))->toBe(1);
});

it('keeps one listing per table (dual-review FR-1)', function (): void {
    $memo = app(SchemaColumns::class);

    $invoices = columnListingQueries('invoices', function () use ($memo): void {
        expect($memo->exist(new Invoice, ['note', 'amount']))->toBeTrue()
            ->and($memo->exist(new PlainRecord, ['note']))->toBeFalse()
            ->and($memo->exist(new Invoice, ['note', 'zzz']))->toBeFalse()
            ->and($memo->exist(new PlainRecord, ['ratio']))->toBeTrue();
    });

    expect($invoices)->toBe(1)
        ->and(columnListingQueries('plain_records', fn () => $memo->exist(new PlainRecord, ['code'])))->toBe(0);
});
