<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Sentinel\DataTransferObjects\HealthCheck;
use RoundlyConsulting\Sentinel\DataTransferObjects\HealthReport;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\HealthStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Anchors\MemoryAnchor;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * I-3: one health report for every misconfiguration that silently weakens the guarantees.
 */
function checked(string $name): HealthCheck
{
    $check = Sentinel::check()->get($name);

    expect($check)->not->toBeNull();

    return $check ?? throw new LogicException;
}

function expectCheck(string $name, HealthStatus $status, string $contains = ''): void
{
    $check = checked($name);

    expect($check->status)->toBe($status, "{$name}: {$check->message}")
        ->and($check->message)->toContain($contains);
}

it('reports every check in a stable order', function (): void {
    invoice();
    MemoryAnchor::install();

    $report = Sentinel::check();

    expect(array_map(static fn (HealthCheck $check): string => $check->name, $report->checks))
        ->toBe(['configuration', 'signing_keys', 'app_key', 'tables', 'models', 'anchors', 'checkpoints', 'schedule', 'retired_keys', 'stores'])
        ->and(array_map(static fn (HealthCheck $check): HealthStatus => $check->status, $report->checks))->each->toBe(HealthStatus::Ok)
        ->and($report->failed())->toBeFalse()
        ->and($report->failures())->toBe([])
        ->and($report->warnings())->toBe([])
        ->and($report->get('nope'))->toBeNull()
        ->and(app(SentinelManager::class)->check()->toArray()['failed'])->toBeFalse();
});

it('checks the configuration', function (string $key, mixed $value, string $message): void {
    config()->set($key, $value);

    expectCheck('configuration', HealthStatus::Failure, $message);

    expect(Sentinel::check()->failed())->toBeTrue();
})->with([
    'a reader' => ['sentinel.context', str_repeat('x', 256), 'sentinel.context'],
    'a ring' => ['sentinel.keys.rings.http.algorithm', 'rot13', 'sentinel.keys.rings.http.algorithm'],
    'an anchor section' => ['sentinel.ledger.anchors', 'cache,9bad', 'sentinel.ledger.anchors'],
    'a schedule task' => ['sentinel.schedule.prune', 'sometimes', 'sentinel.schedule.prune'],
    'a signature profile' => ['sentinel.signatures.profiles.partners', ['ring' => 'nowhere'], 'sentinel.signatures.profiles.partners.ring'],
]);

it('reports an anchor driver section that is not an array', function (): void {
    config()->set('sentinel.ledger.anchors', 'cache');
    config()->set('sentinel.ledger.anchor_drivers.cache', 'not-an-array');

    expectCheck('configuration', HealthStatus::Failure, 'sentinel.ledger.anchor_drivers.cache');
});

it('requires a signing key wherever this node seals', function (): void {
    expectCheck('signing_keys', HealthStatus::Ok, 'default');

    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    expectCheck('signing_keys', HealthStatus::Failure, 'no active signing key in ring(s) default');

    config()->set('sentinel.sealing.auto', 'off');

    expectCheck('signing_keys', HealthStatus::Warning, 'verify-only node');
});

it('checks the rings a sealable model and the ledger use', function (): void {
    archiveRing(withKey: false);
    config()->set('sentinel.ledger.ring', 'archive');
    config()->set('sentinel.models', [definedBy(static fn ($seals) => $seals->seal('archived')->attributes('number')->ring('archive'))]);

    expectCheck('signing_keys', HealthStatus::Failure, 'ring(s) archive');

    config()->set('sentinel.ledger.enabled', false);
    config()->set('sentinel.models', [definedBy(static fn ($seals) => $seals->seal('broken')->attributes('bad-column'))]);

    expectCheck('signing_keys', HealthStatus::Ok, 'default');
});

it('reports an unusable signing key without its material or id', function (): void {
    config()->set('sentinel.keys.rings.default.key', 'base64:'.base64_encode('too short'));
    app(KeyStoreManager::class)->flush();

    $check = checked('signing_keys');

    expect($check->status)->toBe(HealthStatus::Failure)
        ->and($check->message)->toBe('ring [default]: InvalidKeyMaterialException')
        ->and($check->message)->not->toContain(TestCase::ROOT_KEY_ID);
});

it('requires APP_KEY when database keys or idempotency encryption use it', function (): void {
    expectCheck('app_key', HealthStatus::Ok, 'set');

    config()->set('app.key', '');

    expectCheck('app_key', HealthStatus::Failure, 'app.key is empty, but http, idempotency.encrypt encrypt with it');

    config()->set('sentinel.idempotency.encrypt', false);
    config()->set('sentinel.keys.rings.http.driver', 'chain');

    expectCheck('app_key', HealthStatus::Failure, 'but http encrypt');

    config()->set('sentinel.keys.rings.http.driver', 'config');

    expectCheck('app_key', HealthStatus::Ok, 'not needed');
});

it('finds missing tables on every connection they belong to', function (): void {
    expectCheck('tables', HealthStatus::Ok, '6 tables present');

    Schema::drop('sentinel_nonces');

    expectCheck('tables', HealthStatus::Failure, 'missing: sentinel_nonces on [');

    config()->set('sentinel.nonces.store', 'cache');
    config()->set('sentinel.idempotency.store', 'cache');
    config()->set('sentinel.ledger.enabled', false);
    config()->set('sentinel.keys.rings.http.driver', 'config');

    expectCheck('tables', HealthStatus::Ok, '1 tables present');

    config()->set('database.connections.broken', ['driver' => 'sqlite', 'database' => '/nonexistent/dir/sentinel.sqlite', 'prefix' => '']);
    config()->set('sentinel.ledger.connections', [null, 'broken']);

    expectCheck('tables', HealthStatus::Failure, 'sentinel_seals on [broken] (connection failed:');
});

it('checks every sealable model compiles and has its sealed columns', function (): void {
    expectCheck('models', HealthStatus::Warning, 'no sealable models');

    invoice();

    expectCheck('models', HealthStatus::Ok, '0 configured, 1 discovered');

    $missing = definedBy(static fn ($seals) => $seals->seal('ghost')->attributes('number', 'no_such_column'));
    config()->set('sentinel.models', [$missing, definedBy(static fn ($seals) => $seals->seal('broken')->attributes('bad-column'))]);

    $check = checked('models');

    expect($check->status)->toBe(HealthStatus::Failure)
        ->and($check->message)->toContain("[{$missing}] seals columns its table lacks: no_such_column")
        ->and($check->message)->toContain('invalid column [bad-column]');
});

it('warns about stored types that no longer resolve', function (): void {
    invoice();
    DB::table('sentinel_seals')->limit(1)->update(['sealable_type' => 'App\\Models\\Gone']);

    expectCheck('models', HealthStatus::Warning, 'seals of 1 stored type(s) no longer resolve');
});

it('checks the anchors', function (): void {
    expectCheck('anchors', HealthStatus::Warning, 'none configured');

    $anchor = MemoryAnchor::install();

    expectCheck('anchors', HealthStatus::Ok, 'memory');

    $anchor->broken = true;

    expectCheck('anchors', HealthStatus::Failure, 'unreachable: [memory] (RuntimeException)');

    config()->set('sentinel.ledger.anchors', 'nowhere');

    expectCheck('anchors', HealthStatus::Failure, 'could not be checked:');
});

it('warns about a checkpoint backlog', function (): void {
    invoice();

    expectCheck('checkpoints', HealthStatus::Ok, 'no backlog');

    $this->travel(2)->hours();

    expectCheck('checkpoints', HealthStatus::Warning, '2 ledger entries are older than 600s and not checkpointed');

    Sentinel::checkpoint();

    expectCheck('checkpoints', HealthStatus::Ok, 'no backlog');

    config()->set('sentinel.ledger.enabled', false);

    expectCheck('checkpoints', HealthStatus::Ok, 'the ledger is off');
});

it('knows whether the upkeep is scheduled', function (): void {
    expectCheck('schedule', HealthStatus::Ok, 'auto');

    config()->set('sentinel.schedule.enabled', false);
    app()->forgetInstance(Schedule::class);

    expectCheck('schedule', HealthStatus::Warning, 'no sentinel:checkpoint is scheduled');

    app(Schedule::class)->command('sentinel:checkpoint')->everyMinute();

    expectCheck('schedule', HealthStatus::Ok, 'manual');

    config()->set('sentinel.ledger.enabled', false);

    expectCheck('schedule', HealthStatus::Ok, 'manual; the ledger is off');
});

it('counts seals still on revoked, retired or unknown keys — never naming a key', function (): void {
    invoice();
    record();

    expectCheck('retired_keys', HealthStatus::Ok);

    config()->set('sentinel.keys.revoked', 'default:'.TestCase::ROOT_KEY_ID);
    app(KeyStoreManager::class)->flush();
    DB::table('sentinel_seals')->where('sealable_type', PlainRecord::class)->update(['key_id' => 'vanished']);
    DB::table('sentinel_seals')->where('sealable_type', Invoice::class)->where('seal', 'identity')->update(['ring' => 'Old Ring!']);

    $check = checked('retired_keys');

    expect($check->status)->toBe(HealthStatus::Warning)
        ->and($check->message)->toContain('1 seal(s) on revoked keys in ring [default]')
        ->and($check->message)->toContain('1 seal(s) on unknown keys in ring [default]')
        ->and($check->message)->toContain('1 seal(s) on unknown keys in ring [(invalid)]')
        ->and($check->message)->toContain('sentinel:reseal --from-key=<kid>')
        ->and($check->message)->not->toContain(TestCase::ROOT_KEY_ID)->not->toContain('vanished');
});

it('counts seals on retired database keys', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'database');
    app(KeyStoreManager::class)->flush();
    $old = Sentinel::keys()->ring()->generate(Algorithm::HmacSha256)->info->keyId;
    invoice();
    Sentinel::keys()->ring()->retire($old);

    expectCheck('retired_keys', HealthStatus::Warning, '2 seal(s) on retired keys in ring [default]');
});

it('checks that the stores can be built', function (): void {
    expectCheck('stores', HealthStatus::Ok, 'database (idempotency), database (nonces)');

    config()->set('cache.stores.nolock', ['driver' => 'null']);
    config()->set('sentinel.nonces.store', 'cache');
    config()->set('sentinel.nonces.cache_store', 'nolock');
    config()->set('sentinel.idempotency.store', 'custom');

    $check = checked('stores');

    expect($check->status)->toBe(HealthStatus::Failure)
        ->and($check->message)->toContain('the idempotency store cannot be built: Configuration value [sentinel.idempotency.store]')
        ->and($check->message)->toContain('the nonce store cannot be built:')->toContain('atomic locks');
});

it('reports a check that cannot run instead of failing the report', function (): void {
    Schema::drop('sentinel_seals');

    expectCheck('retired_keys', HealthStatus::Failure, 'could not be checked: QueryException');
    expectCheck('models', HealthStatus::Failure, 'could not be checked: QueryException');

    // Discovery is unavailable: the signing check falls back to the configured models.
    expectCheck('signing_keys', HealthStatus::Ok, 'default');
});

it('prints the report and exits 1 on a failure, or on a warning with --strict', function (): void {
    invoice();

    expect(Artisan::call('sentinel:check'))->toBe(0)
        ->and(Artisan::output())->toContain('signing_keys')->toContain('anchors')->toContain('works, with warnings')
        ->and(Artisan::call('sentinel:check', ['--strict' => true]))->toBe(1);

    MemoryAnchor::install();

    expect(Artisan::call('sentinel:check', ['--strict' => true]))->toBe(0)
        ->and(Artisan::output())->toContain('Sentinel is set up correctly');

    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    expect(Artisan::call('sentinel:check'))->toBe(1)
        ->and(Artisan::output())->toContain('Sentinel is not set up correctly');
});

it('prints JSON with a stable shape', function (): void {
    invoice();

    expect(Artisan::call('sentinel:check', ['--json' => true]))->toBe(0);

    $report = json_decode(Artisan::output(), true, 8, JSON_THROW_ON_ERROR);

    expect(array_keys($report))->toBe(['failed', 'checks'])
        ->and($report['failed'])->toBeFalse()
        ->and($report['checks'][5])->toBe(['name' => 'anchors', 'status' => 'warning', 'message' => 'none configured: a rollback of the whole database is undetectable (set SENTINEL_ANCHORS)'])
        ->and(Artisan::call('sentinel:check', ['--json' => true, '--strict' => true]))->toBe(1)
        ->and(json_decode(Artisan::output(), true, 8, JSON_THROW_ON_ERROR)['failed'])->toBeTrue();
});

it('never prints key material or a database key id', function (): void {
    config()->set('sentinel.keys.rings.http.driver', 'database');
    app(KeyStoreManager::class)->flush();
    $kid = Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'secret-kid-77')->info->keyId;
    config()->set('sentinel.keys.revoked', "http:{$kid}");
    invoice();

    Artisan::call('sentinel:check', ['--json' => true]);
    $json = Artisan::output();
    Artisan::call('sentinel:check');
    $human = Artisan::output();

    expect($json.$human)->not->toContain('secret-kid-77')->not->toContain(TestCase::ROOT_KEY)->not->toContain(substr(TestCase::ROOT_KEY, 7))->not->toContain(TestCase::ROOT_KEY_ID)
        ->and(new HealthReport([]))->toBeInstanceOf(HealthReport::class);
});

it('runs under the fake as in production (read-only diagnostics)', function (): void {
    Sentinel::fake();

    expect(Sentinel::check()->get('configuration')?->status)->toBe(HealthStatus::Ok);
});
