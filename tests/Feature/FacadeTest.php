<?php

declare(strict_types=1);

use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\Actions\ExampleSentinelAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\ExampleSentinelData;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\SentinelServiceProvider;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;

/**
 * The public API contract — Actions → Manager → Facade (+ fake) — pinned from day one.
 * Grow these tests with the API: every facade and sub-accessor method through the facade,
 * one DI resolution of the manager, cross-scope refusals, and a passing plus a failing case
 * for every fake assert.
 */
it('pins the facade contract', function (): void {
    expect(Sentinel::class)
        ->toDocumentItsRoot()
        ->toBeFakeable()
        ->toReachEveryAction(__DIR__.'/../../src/Actions');
});

it('runs the example through the facade', function (): void {
    expect(Sentinel::example(new ExampleSentinelData('Ada')))->toBe('Hello, Ada!');
});

it('runs the example through an injected manager', function (): void {
    $manager = app(SentinelManager::class);

    expect($manager)->toBe(app(SentinelManager::class))
        ->and($manager->example(new ExampleSentinelData('Ada')))->toBe('Hello, Ada!');
});

it('runs the example action directly', function (): void {
    expect(app(ExampleSentinelAction::class)->execute(new ExampleSentinelData('Ada')))
        ->toBe('Hello, Ada!');
});

it('resolves the action through the container so a host override applies', function (): void {
    app()->bind(ExampleSentinelAction::class, static fn (): never => throw new RuntimeException('overridden'));

    Sentinel::example(new ExampleSentinelData('Ada'));
})->throws(RuntimeException::class, 'overridden');

it('records facade and injected calls under the fake without running the action', function (): void {
    app()->bind(ExampleSentinelAction::class, static fn (): never => throw new RuntimeException('ran'));

    $fake = Sentinel::fake();

    Sentinel::example(new ExampleSentinelData('Ada'));
    app(SentinelManager::class)->example(new ExampleSentinelData('Grace'));

    expect(app(SentinelManager::class))->toBeInstanceOf(SentinelFake::class);

    $fake->assertExampleCalled();
    $fake->assertExampleCalled(static fn (ExampleSentinelData $data): bool => $data->name === 'Ada');
    Sentinel::assertExampleCalled(static fn (ExampleSentinelData $data): bool => $data->name === 'Grace');
});

it('fails assertExampleCalled when nothing was called', function (): void {
    Sentinel::fake()->assertExampleCalled();
})->throws(ExpectationFailedException::class, 'Expected example() to be called, but it was not.');

it('fails assertExampleCalled when no call matches', function (): void {
    $fake = Sentinel::fake();

    Sentinel::example(new ExampleSentinelData('Ada'));

    $fake->assertExampleCalled(static fn (ExampleSentinelData $data): bool => $data->name === 'Grace');
})->throws(ExpectationFailedException::class, 'no call matched');

it('passes assertNothingCalled on an untouched fake', function (): void {
    Sentinel::fake()->assertNothingCalled();
});

it('fails assertNothingCalled after a call', function (): void {
    $fake = Sentinel::fake();

    Sentinel::example(new ExampleSentinelData('Ada'));

    $fake->assertNothingCalled();
})->throws(ExpectationFailedException::class, 'example() was called 1 time(s)');

it('declares no global alias, so a host using cartalyst/sentinel keeps its own Sentinel', function (): void {
    // cartalyst/sentinel registers the global alias `Sentinel`; a package-discovered alias of
    // ours would silently replace it. laravel/sentinel ships Laravel\Sentinel\Sentinel (no
    // alias). Hosts import RoundlyConsulting\Sentinel\Facades\Sentinel explicitly.
    /** @var array{extra: array{laravel: array<string, mixed>}} $composer */
    $composer = json_decode((string) file_get_contents(__DIR__.'/../../composer.json'), true, flags: JSON_THROW_ON_ERROR);

    expect($composer['extra']['laravel'])->not->toHaveKey('aliases')
        ->and($composer['extra']['laravel']['providers'] ?? null)->toBe([SentinelServiceProvider::class])
        ->and(class_exists('Sentinel'))->toBeFalse();
});
