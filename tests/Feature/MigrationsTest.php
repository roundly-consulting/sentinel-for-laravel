<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use RoundlyConsulting\PackageToolkit\Enums\DatabaseDriver;
use RoundlyConsulting\Sentinel\SentinelServiceProvider;
use RoundlyConsulting\Testing\Database\DriverMatrix;

$migrations = __DIR__.'/../../database/migrations';

it('never auto-loads its migrations — the host publishes them', function (): void {
    expect(SentinelServiceProvider::class)->toNotAutoLoadMigrations();
});

it('publishes its migrations timestamp-injected into the host', function (): void {
    expect(SentinelServiceProvider::class)->toPublishMigrationsTimestamped('sentinel-migrations', 1);
});

it('migrates forward only — no migration defines down()', function () use ($migrations): void {
    $files = glob($migrations.'/*.php') ?: [];

    expect($files)->toHaveCount(1);

    foreach ($files as $file) {
        expect((string) file_get_contents($file))->not->toContain('function down(');
    }
});

it('applies its migrations on postgres', function () use ($migrations): void {
    expect($migrations)->toApplyOnConnection('pgsql', migrations: 1);
})->skip(fn (): bool => ! test()->connectionAvailable('pgsql'), 'no postgres connection available');

it('applies its migrations on mysql', function () use ($migrations): void {
    expect($migrations)->toApplyOnConnection('mysql', migrations: 1);
})->skip(fn (): bool => ! test()->connectionAvailable('mysql'), 'no mysql connection available');

it('runs the suite on the engine the leg names', function (): void {
    expect(DatabaseDriver::current()->value)->toBe(DriverMatrix::driver())
        ->and(DB::connection()->getDriverName())->toBe(DriverMatrix::driver());
});
