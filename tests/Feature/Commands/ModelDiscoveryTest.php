<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * I-10: `sentinel:verify` without arguments scans every sealable model Sentinel knows — the
 * configured ones, then every class that has seals — and never reports green over nothing.
 */
afterEach(function (): void {
    Relation::morphMap([], false);
});

it('discovers sealed classes by class name and by morph alias, configured first', function (): void {
    Relation::morphMap(['plain-record' => PlainRecord::class]);
    invoice();
    record();

    expect(DB::table('sentinel_seals')->distinct()->pluck('sealable_type')->sort()->values()->all())->toBe([Invoice::class, 'plain-record'])
        ->and(Sentinel::sealables())->toBe([Invoice::class, PlainRecord::class])
        ->and(app(SentinelManager::class)->sealables())->toBe([Invoice::class, PlainRecord::class]);

    config()->set('sentinel.models', [PlainRecord::class]);

    expect(Sentinel::sealables())->toBe([PlainRecord::class, Invoice::class]);
});

it('discovers classes that only have ledger history', function (): void {
    $invoice = invoice();
    DB::table('sentinel_seals')->delete();

    expect(Sentinel::sealables())->toBe([Invoice::class])
        ->and(DB::table('sentinel_ledger')->where('sealable_id', $invoice->id)->exists())->toBeTrue();
});

it('scans the discovered models when given none', function (): void {
    invoice();
    record();

    [$status, $output] = [Artisan::call('sentinel:verify', ['--json' => true]), Artisan::output()];
    $report = json_decode($output, true, 16, JSON_THROW_ON_ERROR);

    expect($status)->toBe(0)
        ->and($report['models'])->toBe([Invoice::class, PlainRecord::class])
        ->and($report['unresolved_types'])->toBe([])
        ->and($report['scanned'])->toBe(3);
});

it('warns about stored types that no longer resolve to a sealable model', function (): void {
    invoice();
    record();
    $first = DB::table('sentinel_seals')->orderBy('id')->value('id');
    DB::table('sentinel_seals')->where('id', $first)->update(['sealable_type' => 'App\\Models\\Gone']);
    DB::table('sentinel_ledger')->where('sealable_type', PlainRecord::class)->update(['sealable_type' => User::class]);
    DB::table('sentinel_seals')->where('sealable_type', PlainRecord::class)->update(['sealable_type' => User::class]);

    $status = Artisan::call('sentinel:verify', ['--fail-on' => ['tampered']]);
    $output = Artisan::output();

    expect($status)->toBe(0)
        ->and($output)->toContain('Seals of [App\\Models\\Gone] are not verified')
        ->and($output)->toContain('Seals of ['.User::class.'] are not verified')
        ->and(Sentinel::sealables())->toBe([Invoice::class]);

    Artisan::call('sentinel:verify', ['--json' => true, '--fail-on' => ['tampered']]);

    expect(json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR)['unresolved_types'])->toBe(['App\\Models\\Gone', User::class]);
});

it('never prints an unprintable stored type', function (): void {
    invoice();
    DB::table('sentinel_seals')->limit(1)->update(['sealable_type' => "Evil\x1b[31m"]);

    Artisan::call('sentinel:verify', ['--fail-on' => ['tampered']]);

    expect(Artisan::output())->toContain('Seals of [(invalid)] are not verified')->not->toContain("\x1b[31m");
});

it('reads every ledger connection', function (): void {
    config()->set('database.connections.second', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '', 'foreign_key_constraints' => true]);

    foreach (['sentinel_seals', 'sentinel_ledger'] as $table) {
        Schema::connection('second')->create($table, static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('sealable_type');
        });
    }

    DB::connection('second')->table('sentinel_ledger')->insert(['sealable_type' => PlainRecord::class]);
    config()->set('sentinel.ledger.connections', [null, 'second']);
    invoice();

    expect(Sentinel::sealables())->toBe([Invoice::class, PlainRecord::class]);
});

it('exits 2 when there is nothing to verify, unless an empty run is allowed', function (): void {
    expect(Artisan::call('sentinel:verify'))->toBe(2)
        ->and(Artisan::output())->toContain('Nothing to verify: pass model classes, list them in sentinel.models, or seal rows first')
        ->and(Artisan::call('sentinel:verify', ['--ledger' => true]))->toBe(2)
        ->and(Artisan::call('sentinel:verify', ['--allow-empty' => true]))->toBe(0)
        ->and(Artisan::output())->toContain('No models to scan')
        ->and(Artisan::call('sentinel:verify', ['--allow-empty' => true, '--ledger' => true, '--json' => true]))->toBe(0);

    $report = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);

    expect($report['models'])->toBe([])
        ->and($report['scanned'])->toBe(0)
        ->and($report['ledger']['clean'])->toBeTrue();
});

it('still scans only the models it is given', function (): void {
    invoice();
    record();

    Artisan::call('sentinel:verify', ['model' => [PlainRecord::class], '--json' => true]);

    expect(json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR))->toMatchArray(['models' => [PlainRecord::class], 'scanned' => 1]);
});

it('reports configured and discovered models in about, and survives an unmigrated database', function (): void {
    config()->set('sentinel.models', [PlainRecord::class]);
    invoice();

    Artisan::call('about', ['--only' => 'sentinel']);

    expect(Artisan::output())->toMatch('/Sealable models\W+1 configured, 1 discovered/');

    Schema::drop('sentinel_seals');
    Artisan::call('about', ['--only' => 'sentinel']);

    expect(Artisan::output())->toMatch('/Sealable models\W+1 configured, discovery unavailable/');

    config()->set('sentinel.ledger.connections', ['not-configured']);
    Artisan::call('about', ['--only' => 'sentinel']);

    expect(Artisan::output())->toMatch('/Sealable models\W+1 configured, discovery unavailable/');
});
