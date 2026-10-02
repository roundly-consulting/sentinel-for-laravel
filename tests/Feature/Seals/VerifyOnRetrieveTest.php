<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

function retrieving(?Reaction $reaction = null): string
{
    return definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount')->verifyOnRetrieve($reaction));
}

/**
 * §10 item 22: verify-on-retrieve, opt-in per seal.
 */
it('throws when a tampered model is retrieved', function (): void {
    Event::fake([TamperDetected::class]);
    $class = retrieving(Reaction::Throw);
    $model = $class::query()->create(['number' => 'r-1', 'amount' => '5.00']);

    expect($class::query()->find($model->getKey())?->getKey())->toBe($model->getKey());

    DB::table('invoices')->where('id', $model->getKey())->update(['amount' => '0.00']);

    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class, 'tampered: mac');

    Event::assertDispatched(TamperDetected::class, static fn (TamperDetected $event): bool => $event->context === VerificationContext::Retrieve);
});

it('only fires an event, or only logs, when asked to', function (): void {
    Event::fake([TamperDetected::class]);
    $log = Log::spy();
    $log->shouldReceive('channel')->andReturn($log);

    $evented = retrieving(Reaction::Event);
    $logged = retrieving(Reaction::Log);
    $a = $evented::query()->create(['number' => 'e', 'amount' => '1.00']);
    $b = $logged::query()->create(['number' => 'l', 'amount' => '1.00']);
    DB::table('invoices')->update(['amount' => '9.00']);

    expect($evented::query()->find($a->getKey()))->not->toBeNull();
    Event::assertDispatchedTimes(TamperDetected::class, 1);
    $log->shouldNotHaveReceived('warning');

    expect($logged::query()->find($b->getKey()))->not->toBeNull();
    Event::assertDispatchedTimes(TamperDetected::class, 1);
    $log->shouldHaveReceived('warning')->once();
});

it('takes the configured reaction when the seal names none', function (): void {
    $class = retrieving();
    $model = $class::query()->create(['number' => 'd', 'amount' => '1.00']);
    DB::table('invoices')->update(['amount' => '9.00']);
    config()->set('sentinel.verification.retrieve_reaction', 'event');

    expect($class::query()->find($model->getKey()))->not->toBeNull();

    config()->set('sentinel.verification.retrieve_reaction', 'throw');

    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class);
});

it('skips a partial select instead of reporting it', function (): void {
    Event::fake([TamperDetected::class]);
    $class = retrieving(Reaction::Throw);
    $model = $class::query()->create(['number' => 'p', 'amount' => '1.00']);
    DB::table('invoices')->update(['amount' => '9.00']);

    expect($class::query()->select('id', 'number')->find($model->getKey())?->getKey())->toBe($model->getKey());

    Event::assertNotDispatched(TamperDetected::class);
});

it('verifies the loaded values without reading the row again', function (): void {
    $class = retrieving(Reaction::Throw);
    $model = $class::query()->create(['number' => 'q', 'amount' => '1.00']);

    DB::enableQueryLog();
    $class::query()->find($model->getKey());
    $queries = DB::getQueryLog();
    DB::disableQueryLog();

    // The SELECT of the model and the one of its seal row — no read-back, no ledger query.
    expect($queries)->toHaveCount(2);
});

it('lets an acknowledgement load a tampered model', function (): void {
    $class = retrieving(Reaction::Throw);
    $model = $class::query()->create(['number' => 'a', 'amount' => '1.00']);
    DB::table('invoices')->update(['amount' => '9.00']);

    $loaded = Sentinel::withoutVerification(static fn () => $class::query()->findOrFail($model->getKey()));

    expect(Sentinel::acknowledge($loaded, 'INC-1 fixed')->acknowledged)->toBeTrue()
        ->and($class::query()->find($model->getKey()))->not->toBeNull();
});

it('never recurses when a computed field loads other guarded models', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('related')->attributes('number')
        ->computed('siblings', static fn ($model): array => $model::query()->whereKeyNot($model->getKey())->get()->map->number->sort()->values()->all())
        ->verifyOnRetrieve(Reaction::Throw));

    $class::query()->create(['number' => 'one']);
    $class::query()->create(['number' => 'two']);

    // Each seal covers the siblings as they were; re-seal the first now that both exist.
    $first = Sentinel::withoutVerification(static fn () => $class::query()->orderBy('id')->firstOrFail());
    Sentinel::seal($first);

    expect($class::query()->orderBy('id')->get())->toHaveCount(2);
});

it('applies faked statuses and reactions under the fake', function (): void {
    $class = retrieving(Reaction::Throw);
    $model = $class::query()->create(['number' => 'f']);
    $fake = Sentinel::fake();

    expect($class::query()->find($model->getKey()))->not->toBeNull();

    $fake->fakeStatus($model, VerificationStatus::Tampered);

    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class)
        ->and(Sentinel::withoutVerification(static fn () => $class::query()->find($model->getKey())))->not->toBeNull();

    $fake->assertVerified($model, 'guarded');
});
