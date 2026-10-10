<?php

declare(strict_types=1);

use Illuminate\Console\Events\ScheduledTaskFailed;
use Illuminate\Console\Events\ScheduledTaskSkipped;
use Illuminate\Console\Events\ScheduledTaskStarting;
use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Log\LogManager;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Enums\HealthStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Idempotency\ResponseVault;
use RoundlyConsulting\Sentinel\Idempotency\Stores\CacheIdempotencyStore;

/**
 * G34: a host that gets Sentinel only through another package never runs its migrations, yet
 * the upkeep schedule is on by default. Its tasks must skip there instead of failing every
 * minute — without a `SENTINEL_SCHEDULE=false` the host would have to know to set.
 */
const UPKEEP = ['sentinel:checkpoint', 'sentinel:verify --allow-empty --ledger', 'sentinel:prune'];

const SENTINEL_TABLES = ['sentinel_keys', 'sentinel_checkpoints', 'sentinel_ledger', 'sentinel_seals', 'sentinel_idempotency_keys', 'sentinel_nonces'];

beforeEach(function (): void {
    // Midnight in the app's timezone: checkpoint (every minute), verify and prune (daily) are all due.
    Carbon::setTestNow(Carbon::parse('2026-10-11 00:00:00', 'Europe/Bratislava'));
});

afterEach(function (): void {
    Carbon::setTestNow();
});

/**
 * The Sentinel events `schedule:run` finds due, by command line, from a fresh scheduler.
 *
 * @return array<string, ScheduledEvent>
 */
function dueUpkeep(): array
{
    app()->forgetInstance(Schedule::class);
    $events = [];

    foreach (app(Schedule::class)->dueEvents(app()) as $event) {
        $command = (string) preg_replace("/^.*'artisan' /", '', (string) $event->command);

        if (str_starts_with($command, 'sentinel:')) {
            $events[$command] = $event;
        }
    }

    return $events;
}

/**
 * The command lines whose filters let `schedule:run` start them.
 *
 * @param  array<string, ScheduledEvent>  $events
 * @return list<string>
 */
function runnableUpkeep(array $events): array
{
    return array_keys(array_filter($events, static fn (ScheduledEvent $event): bool => $event->filtersPass(app())));
}

it('has none of Sentinel\'s tables, and registers its upkeep as on any host', function (): void {
    foreach (SENTINEL_TABLES as $table) {
        expect(Schema::hasTable($table))->toBeFalse($table);
    }

    $events = dueUpkeep();

    expect(array_keys($events))->toBe(UPKEEP)
        ->and($events['sentinel:checkpoint']->expression)->toBe('* * * * *')
        ->and($events['sentinel:verify --allow-empty --ledger']->expression)->toBe('0 0 * * *')
        ->and($events['sentinel:prune']->expression)->toBe('0 0 * * *');
});

it('runs its schedule without a failure', function (): void {
    // What `schedule:run` does with each due event, in process: start it only when its
    // filters pass. Without the tables, a started task fails.
    foreach (dueUpkeep() as $command => $event) {
        if ($event->filtersPass(app())) {
            expect(Artisan::call($command))->toBe(0, "{$command} ran and failed");
        }
    }

    Event::fake([ScheduledTaskStarting::class, ScheduledTaskSkipped::class, ScheduledTaskFailed::class]);

    expect(Artisan::call('schedule:run'))->toBe(0)
        ->and(Artisan::output())->toContain('No scheduled commands are ready to run.');

    Event::assertDispatchedTimes(ScheduledTaskSkipped::class, 3);
    Event::assertNotDispatched(ScheduledTaskStarting::class);
    Event::assertNotDispatched(ScheduledTaskFailed::class);
});

it('looks for the tables once per run, not once per task', function (): void {
    $events = dueUpkeep();
    $queries = 0;
    DB::listen(static function () use (&$queries): void {
        $queries++;
    });

    expect(runnableUpkeep($events))->toBe([]);

    // One lookup per table the shipped configuration needs, shared by the three tasks.
    $first = $queries;

    expect(runnableUpkeep($events))->toBe([])
        ->and($first)->toBe(count(SENTINEL_TABLES))
        ->and($queries)->toBe($first);
});

it('runs the upkeep on the first run after the migrations', function (): void {
    expect(runnableUpkeep(dueUpkeep()))->toBe([]);

    Artisan::call('migrate', ['--path' => realpath(__DIR__.'/../../database/migrations'), '--realpath' => true]);

    // Every `schedule:run` is a process of its own: a new scope, a new look.
    app()->forgetScopedInstances();

    expect(runnableUpkeep(dueUpkeep()))->toBe(UPKEEP);
});

it('still prunes the stores that are not Sentinel tables', function (string $idempotency, string $nonces, array $runnable): void {
    config()->set('sentinel.idempotency.store', $idempotency);
    config()->set('sentinel.nonces.store', $nonces);

    expect(runnableUpkeep(dueUpkeep()))->toBe($runnable);
})->with([
    'both in the cache' => ['cache', 'cache', ['sentinel:prune']],
    'idempotency keys in the database' => ['database', 'cache', []],
    'nonces in the database' => ['cache', 'database', []],
]);

it('looks at the store the host bound, not only the configured one', function (): void {
    config()->set('sentinel.nonces.store', 'cache');
    app()->bind(IdempotencyStore::class, static fn (Application $app): IdempotencyStore => new CacheIdempotencyStore(
        $app->make('cache')->store(),
        $app->make(ResponseVault::class),
        $app->make(LogManager::class),
    ));

    expect(runnableUpkeep(dueUpkeep()))->toBe(['sentinel:prune']);
});

it('runs a task it cannot rule out, which then reports as it always did', function (Closure $setUp, array $runnable): void {
    $setUp();

    expect(runnableUpkeep(dueUpkeep()))->toBe($runnable);
})->with([
    'an unreachable ledger connection' => [function (): void {
        config()->set('database.connections.broken', ['driver' => 'sqlite', 'database' => '/nonexistent/dir/sentinel.sqlite', 'prefix' => '']);
        config()->set('sentinel.ledger.connections', [null, 'broken']);
    }, UPKEEP],
    'a configuration it cannot read' => [function (): void {
        config()->set('sentinel.ledger.connections', 'not-a-list');
    }, UPKEEP],
    'a store that cannot be built' => [function (): void {
        app()->bind(IdempotencyStore::class, static fn (): IdempotencyStore => throw new RuntimeException('no store'));
    }, ['sentinel:prune']],
]);

it('fails sentinel:check while its upkeep is skipped', function (): void {
    $report = Sentinel::check();

    expect($report->get('schedule')?->status)->toBe(HealthStatus::Failure)
        ->and($report->get('schedule')?->message)->toBe('auto (sentinel.schedule), but checkpoint, verify, prune skip every run: none of Sentinel\'s tables exists — publish and run the migrations (php artisan vendor:publish --tag=sentinel-migrations)')
        ->and($report->get('tables')?->status)->toBe(HealthStatus::Failure)
        ->and(Artisan::call('sentinel:check'))->toBe(1)
        ->and(Artisan::output())->toContain('checkpoint, verify, prune skip every run');

    config()->set('sentinel.idempotency.store', 'cache');
    config()->set('sentinel.nonces.store', 'cache');

    expect(Sentinel::check()->get('schedule')?->message)->toStartWith('auto (sentinel.schedule), but checkpoint, verify skip every run');

    // Scheduling by hand is still the host's call, reported as before.
    config()->set('sentinel.schedule.enabled', false);
    app()->forgetInstance(Schedule::class);

    expect(Sentinel::check()->get('schedule')?->status)->toBe(HealthStatus::Warning)
        ->and(Sentinel::check()->get('schedule')?->message)->toContain('no sentinel:checkpoint is scheduled');
});

it('says in about that the upkeep is skipped', function (): void {
    Artisan::call('about', ['--only' => 'sentinel']);

    expect(Artisan::output())->toMatch('/Schedule\W+auto \(checkpoint, verify, prune skipped: no tables\)/');

    config()->set('sentinel.schedule.enabled', false);
    Artisan::call('about', ['--only' => 'sentinel']);

    expect(Artisan::output())->toMatch('/Schedule\W+manual/');
});
