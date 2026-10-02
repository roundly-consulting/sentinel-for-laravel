<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Jobs\Middleware\Idempotent;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Jobs\ChargeJob;

/**
 * I-2: a job dispatched twice (a redelivered webhook) runs once.
 */
beforeEach(function (): void {
    ChargeJob::$runs = 0;
    ChargeJob::$behaviour = [];
});

it('runs the same job once', function (): void {
    ChargeJob::dispatch('evt_1');
    ChargeJob::dispatch('evt_1');
    ChargeJob::dispatch('evt_2');

    expect(ChargeJob::$runs)->toBe(2)
        ->and(IdempotencyKey::query()->where('scope', 'webhooks')->count())->toBe(2);
});

it('runs a retry after the first attempt threw', function (): void {
    ChargeJob::$behaviour = ['throw'];

    expect(fn () => ChargeJob::dispatch('evt_3'))->toThrow(RuntimeException::class, 'gateway down');

    ChargeJob::dispatch('evt_3');
    ChargeJob::dispatch('evt_3');

    expect(ChargeJob::$runs)->toBe(2);
});

it('gives the key back when the job releases or fails itself', function (string $behaviour): void {
    ChargeJob::$behaviour = [$behaviour];

    ChargeJob::dispatch('evt_4');
    ChargeJob::dispatch('evt_4');
    ChargeJob::dispatch('evt_4');

    expect(ChargeJob::$runs)->toBe(2);
})->with(['release', 'fail']);

it('releases an in-flight duplicate back onto the queue', function (): void {
    $middleware = new Idempotent('stripe:evt_5', scope: 'webhooks', releaseAfter: 15);
    $duplicate = new class
    {
        /** @var list<int> */
        public array $released = [];

        public function release(int $delay = 0): void
        {
            $this->released[] = $delay;
        }
    };
    $ran = false;

    // The first run holds the key while the duplicate arrives.
    Sentinel::idempotency()->run('stripe:evt_5', 'webhooks', static function () use ($middleware, $duplicate, &$ran): null {
        $middleware->handle($duplicate, static function () use (&$ran): void {
            $ran = true;
        });

        return null;
    });

    expect($duplicate->released)->toBe([60])
        ->and($ran)->toBeFalse();
});

it('rethrows for an in-flight duplicate that cannot be released', function (): void {
    $middleware = new Idempotent('stripe:evt_6');

    expect(fn () => Sentinel::idempotency()->run('stripe:evt_6', 'jobs', static fn (): mixed => $middleware->handle(new stdClass, static fn (): null => null)))
        ->toThrow(IdempotencyRequestInProgressException::class);
});

it('records the run under the fake', function (): void {
    $fake = Sentinel::fake();

    ChargeJob::dispatch('evt_7');
    ChargeJob::dispatch('evt_7');

    $fake->assertIdempotentRun('stripe:evt_7');
    $fake->assertIdempotentRun('stripe:evt_7', replayed: true);

    expect(ChargeJob::$runs)->toBe(1)
        ->and($fake->recorded('runIdempotent')[0]->arguments)->toBeInstanceOf(IdempotentCall::class);
});

it('validates the key when the middleware is built', function (string $key, string $scope, ?int $ttl, int $releaseAfter): void {
    expect(fn () => new Idempotent($key, $scope, $ttl, $releaseAfter))->toThrow(InvalidIdempotencyKeyException::class);
})->with([
    'empty key' => ['', 'jobs', null, 10],
    'long key' => [str_repeat('k', 256), 'jobs', null, 10],
    'empty scope' => ['k', '', null, 10],
    'long scope' => ['k', str_repeat('s', 256), null, 10],
    'short ttl' => ['k', 'jobs', 59, 10],
    'long ttl' => ['k', 'jobs', 2592001, 10],
    'no release delay' => ['k', 'jobs', null, 0],
]);
