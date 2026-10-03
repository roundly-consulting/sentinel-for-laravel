<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Event;
use Illuminate\Console\Scheduling\Schedule;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * I-11: Sentinel schedules its own upkeep — checkpoint, verify, prune — unless told not to.
 *
 * @return array<string, Event>
 */
function sentinelEvents(): array
{
    // A fresh scheduler, as `schedule:run` builds one per run.
    app()->forgetInstance(Schedule::class);
    $events = [];

    foreach (app(Schedule::class)->events() as $event) {
        $command = (string) preg_replace("/^.*'artisan' /", '', (string) $event->command);

        if (str_starts_with($command, 'sentinel:')) {
            $events[$command] = $event;
        }
    }

    return $events;
}

it('schedules checkpoint, verify and prune by default', function (): void {
    $events = sentinelEvents();

    expect(array_keys($events))->toBe(['sentinel:checkpoint', 'sentinel:verify --allow-empty --ledger', 'sentinel:prune'])
        ->and($events['sentinel:checkpoint']->expression)->toBe('* * * * *')
        ->and($events['sentinel:verify --allow-empty --ledger']->expression)->toBe('0 0 * * *')
        ->and($events['sentinel:prune']->expression)->toBe('0 0 * * *')
        ->and($events['sentinel:checkpoint']->withoutOverlapping)->toBeTrue()
        ->and($events['sentinel:checkpoint']->onOneServer)->toBeTrue()
        ->and($events['sentinel:checkpoint']->description)->toBe('Sentinel: checkpoint and anchor the ledger');
});

it('takes the configured frequencies, and turns single tasks off', function (): void {
    config()->set('sentinel.schedule.checkpoint', 'everyFiveMinutes');
    config()->set('sentinel.schedule.verify', 'hourly');
    config()->set('sentinel.schedule.prune', 'off');

    $events = sentinelEvents();

    expect(array_keys($events))->toBe(['sentinel:checkpoint', 'sentinel:verify --allow-empty --ledger'])
        ->and($events['sentinel:checkpoint']->expression)->toBe('*/5 * * * *')
        ->and($events['sentinel:verify --allow-empty --ledger']->expression)->toBe('0 * * * *');

    // Blank is not set: the shipped daily verify, never silently off. Only null or `off` is off.
    config()->set('sentinel.schedule.verify', '');

    expect(array_keys(sentinelEvents()))->toBe(['sentinel:checkpoint', 'sentinel:verify --allow-empty --ledger'])
        ->and(sentinelEvents()['sentinel:verify --allow-empty --ledger']->expression)->toBe('0 0 * * *');

    config()->set('sentinel.schedule.verify', null);

    expect(array_keys(sentinelEvents()))->toBe(['sentinel:checkpoint']);
});

it('schedules no checkpoint and verifies without --ledger while the ledger is off', function (): void {
    config()->set('sentinel.ledger.enabled', 'off');

    expect(array_keys(sentinelEvents()))->toBe(['sentinel:verify --allow-empty', 'sentinel:prune']);
});

it('schedules nothing when disabled', function (string $value): void {
    config()->set('sentinel.schedule.enabled', $value);

    expect(sentinelEvents())->toBe([]);
})->with(['false', 'off', '0']);

it('refuses an unknown frequency', function (mixed $frequency): void {
    config()->set('sentinel.schedule.verify', $frequency);

    expect(fn () => Settings::scheduleFrequency('verify'))->toThrow(InvalidSentinelConfigurationException::class, 'sentinel.schedule.verify')
        ->and(fn () => app(Schedule::class))->toThrow(InvalidSentinelConfigurationException::class);
})->with(['everySecond', 'cron', 'dailyAt', 'DAILY', 5, [['daily']]]);

it('accepts every allowed frequency', function (string $frequency): void {
    config()->set('sentinel.schedule.prune', $frequency);

    expect(Settings::scheduleFrequency('prune'))->toBe($frequency)
        ->and(sentinelEvents())->toHaveKey('sentinel:prune');
})->with(Settings::FREQUENCIES);

it('knows only its own upkeep tasks', function (): void {
    expect(fn () => Settings::scheduleFrequency('backup'))->toThrow(InvalidSentinelConfigurationException::class, 'has no task [backup]');
});
