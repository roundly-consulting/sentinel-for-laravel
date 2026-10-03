<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * I-7: scans narrowed to a query, chunked, with progress for long runs.
 */
function tenantInvoices(): void
{
    foreach ([7, 7, 7, 8] as $tenant) {
        invoice(['tenant_id' => $tenant]);
    }

    // One of tenant 8's invoices was changed out of band.
    DB::table('invoices')->where('tenant_id', 8)->update(['amount' => '0.01']);
}

it('scans only the rows a closure selects, in chunks', function (): void {
    tenantInvoices();

    $tenant7 = Sentinel::model(Invoice::class)->scan('financial', chunk: 2, where: static fn (Builder $query) => $query->where('tenant_id', 7));
    $tenant8 = Sentinel::model(Invoice::class)->scan('financial', where: static fn (Builder $query) => $query->where('tenant_id', 8));

    expect($tenant7->scanned)->toBe(3)
        ->and($tenant7->hasFindings())->toBeFalse()
        ->and($tenant8->scanned)->toBe(1)
        ->and($tenant8->count(VerificationStatus::Tampered))->toBe(1);
});

it('scans the rows a builder of the model selects, ignoring its order', function (): void {
    tenantInvoices();

    $report = Sentinel::scan(new ScanOptions([Invoice::class], 'financial', 1, where: Invoice::query()->where('tenant_id', 7)->orderByDesc('number')));

    expect($report->scanned)->toBe(3);
});

it('includes soft-deleted rows, as the whole-table scan does', function (): void {
    tenantInvoices();
    Invoice::query()->where('tenant_id', 7)->firstOrFail()->delete();

    expect(Sentinel::model(Invoice::class)->scan('financial', where: static fn (Builder $query) => $query->where('tenant_id', 7))->scanned)->toBe(3);
});

it('refuses another model\'s query and a narrowed scan of several models', function (): void {
    expect(fn () => Sentinel::model(Invoice::class)->scan(where: PlainRecord::query()))->toThrow(SealingMisconfiguredException::class, 'The query selects')
        ->and(fn () => Sentinel::scan(new ScanOptions([Invoice::class, PlainRecord::class], where: static fn ($query) => $query)))
        ->toThrow(SealingMisconfiguredException::class, 'exactly one model class');
});

it('combines a where with a limit and caps the findings', function (): void {
    tenantInvoices();
    DB::table('invoices')->update(['amount' => '0.02']);

    $report = Sentinel::model(Invoice::class)->scan('financial', where: static fn (Builder $query) => $query->where('tenant_id', 7), limit: 2, maxFindings: 1);

    expect($report->scanned)->toBe(2)
        ->and($report->findings)->toHaveCount(1)
        ->and($report->truncated)->toBeTrue();
});

it('reports progress after every chunk of scans, re-seals and baselines', function (): void {
    tenantInvoices();
    $seen = [];
    $record = static function (int $processed) use (&$seen): void {
        $seen[] = $processed;
    };

    Sentinel::model(Invoice::class)->scan('financial', chunk: 2, progress: $record);
    $scan = $seen;
    $seen = [];
    Sentinel::model(Invoice::class)->scan('financial', chunk: 3, limit: 2, progress: $record);
    $limited = $seen;
    $seen = [];
    Sentinel::model(Invoice::class)->reseal(chunk: 3, progress: $record);
    $reseal = $seen;
    $seen = [];
    config()->set('sentinel.sealing.allow_suspension', true);
    Sentinel::withoutSealing(static fn () => record(), 'import');
    Sentinel::model(PlainRecord::class)->sealMissing('adopted', progress: $record);

    expect($scan)->toBe([2, 4])
        ->and($limited)->toBe([2])
        ->and($reseal)->toBe([3, 4])
        ->and($seen)->toBe([1]);
});

it('narrows scans and reports progress under the fake as in production', function (): void {
    tenantInvoices();
    $fake = Sentinel::fake();
    $fake->fakeStatus(Invoice::query()->where('tenant_id', 8)->firstOrFail(), VerificationStatus::Tampered, 'financial');
    $seen = [];
    $record = static function (int $processed) use (&$seen): void {
        $seen[] = $processed;
    };

    $tenant7 = Sentinel::model(Invoice::class)->scan('financial', chunk: 2, where: static fn (Builder $query) => $query->where('tenant_id', 7), progress: $record);
    $tenant8 = Sentinel::model(Invoice::class)->scan('financial', where: Invoice::query()->where('tenant_id', 8));
    $scanProgress = $seen;
    $seen = [];
    Sentinel::reseal(new ResealOptions(Invoice::class, chunk: 3, progress: $record));
    $resealProgress = $seen;
    $seen = [];
    Sentinel::sealMissing(new BaselineOptions(PlainRecord::class, null, 'adopted', progress: $record));

    expect($tenant7->scanned)->toBe(3)
        ->and($tenant8->count(VerificationStatus::Tampered))->toBe(1)
        ->and($scanProgress)->toBe([2, 3])
        ->and($resealProgress)->toBe([3, 4])
        ->and($seen)->toBe([])
        ->and(Sentinel::model(Invoice::class)->scan(limit: 1)->scanned)->toBe(2)
        ->and(fn () => Sentinel::scan(new ScanOptions([Invoice::class, PlainRecord::class], where: static fn ($query) => $query)))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::model(Invoice::class)->scan(where: PlainRecord::query()))->toThrow(SealingMisconfiguredException::class);

    $fake->assertScanned(Invoice::class);
});

it('shows a progress bar on a decorated terminal, never with --json', function (string $command, array $parameters, bool $shown): void {
    invoice();
    $output = new BufferedOutput(decorated: true);

    Artisan::call($command, $parameters, $output);

    expect(str_contains($output->fetch(), ' rows '))->toBe($shown);
})->with([
    'verify' => ['sentinel:verify', ['model' => [Invoice::class]], true],
    'verify --json' => ['sentinel:verify', ['model' => [Invoice::class], '--json' => true], false],
    'reseal' => ['sentinel:reseal', ['model' => Invoice::class], true],
    'seal-missing' => ['sentinel:seal-missing', ['model' => Invoice::class, '--reason' => 'adopted'], true],
]);

it('shows no progress bar when the output is not a terminal', function (): void {
    invoice();
    $output = new BufferedOutput(decorated: false);

    Artisan::call('sentinel:verify', ['model' => [Invoice::class]], $output);

    expect($output->fetch())->not->toContain(' rows ');
});
