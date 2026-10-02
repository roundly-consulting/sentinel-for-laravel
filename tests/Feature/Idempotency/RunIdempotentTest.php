<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\Accessors\IdempotencyAccessor;
use RoundlyConsulting\Sentinel\Actions\Idempotency\RunIdempotentAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyKeyReusedException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResponseUnavailableException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResultException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * §10 item 44: programmatic idempotency for jobs, commands and webhooks.
 */
it('runs once per key and scope, and replays the stored result', function (): void {
    $runs = 0;
    $charge = static function () use (&$runs): array {
        $runs++;

        return ['charge' => 'ch_1', 'amount' => 10.5];
    };

    $first = Sentinel::idempotency()->run('charge:42', 'billing', $charge);
    $second = Sentinel::idempotency()->run('charge:42', 'billing', $charge);
    $elsewhere = app(SentinelManager::class)->idempotency()->run('charge:42', 'other-scope', $charge);
    $raw = app(RunIdempotentAction::class)->execute(new IdempotentCall('charge:42', 'billing', $charge));

    expect($runs)->toBe(2)
        ->and($first->replayed)->toBeFalse()
        ->and($second->replayed)->toBeTrue()
        ->and($second->value)->toBe(['charge' => 'ch_1', 'amount' => 10.5])
        ->and($second->firstSeenAt->eq($first->firstSeenAt))->toBeTrue()
        ->and($elsewhere->replayed)->toBeFalse()
        ->and($raw->replayed)->toBeTrue()
        ->and(Sentinel::idempotency())->toBeInstanceOf(IdempotencyAccessor::class);
});

it('refuses the same key with another fingerprint, or while it still runs', function (): void {
    Sentinel::idempotency()->run('job:1', 'jobs', static fn (): int => 1, fingerprint: 'order 1');

    expect(fn () => Sentinel::idempotency()->run('job:1', 'jobs', static fn (): int => 2, fingerprint: 'order 2'))->toThrow(IdempotencyKeyReusedException::class);

    $inner = null;
    Sentinel::idempotency()->run('job:2', 'jobs', static function () use (&$inner): int {
        try {
            Sentinel::idempotency()->run('job:2', 'jobs', static fn (): int => 0);
        } catch (IdempotencyRequestInProgressException $exception) {
            $inner = $exception;
        }

        return 1;
    });

    expect($inner?->retryAfterSeconds())->toBeGreaterThan(0)
        ->and($inner?->getHeaders())->toHaveKey('Retry-After');
});

it('releases the key when the callback fails, but never after it ran', function (): void {
    expect(fn () => Sentinel::idempotency()->run('job:3', 'jobs', static fn () => throw new RuntimeException('down')))->toThrow(RuntimeException::class, 'down')
        ->and(Sentinel::idempotency()->run('job:3', 'jobs', static fn (): string => 'ok')->value)->toBe('ok')
        ->and(fn () => Sentinel::idempotency()->run('job:4', 'jobs', static fn () => NAN))->toThrow(IdempotentResultException::class, 'completed without a replayable result')
        ->and(fn () => Sentinel::idempotency()->run('job:4', 'jobs', static fn (): int => 4))->toThrow(IdempotentResponseUnavailableException::class);
});

it('forgets a key on request', function (): void {
    Sentinel::idempotency()->run('job:5', 'jobs', static fn (): int => 5);

    expect(Sentinel::idempotency()->forget('job:5', 'jobs'))->toBeTrue()
        ->and(Sentinel::idempotency()->forget('job:5', 'jobs'))->toBeFalse()
        ->and(Sentinel::idempotency()->run('job:5', 'jobs', static fn (): int => 6)->value)->toBe(6);
});

it('validates the key and reports unreplayable records', function (): void {
    expect(fn () => Sentinel::idempotency()->run('', 'jobs', static fn (): int => 1))->toThrow(InvalidIdempotencyKeyException::class);

    Sentinel::idempotency()->run('job:6', 'jobs', static fn (): int => 1);
    IdempotencyKey::query()->toBase()->update(['replayable' => false]);

    expect(fn () => Sentinel::idempotency()->run('job:6', 'jobs', static fn (): int => 1))->toThrow(IdempotentResponseUnavailableException::class);
});

/**
 * §10 item 43: transactional mode commits the handler's writes and the record together.
 */
it('commits or rolls back the handler\'s writes together with the record', function (): void {
    config()->set('sentinel.idempotency.transactional', true);
    Route::post('/tx/{status}', static function (string $status) {
        DB::table('users')->insert(['name' => 'written by the handler']);

        return response('done', (int) $status);
    })->middleware('sentinel.idempotent');

    $this->postJson('/tx/201', [], ['Idempotency-Key' => '"tx-key-0000000000001"'])->assertCreated();
    $this->postJson('/tx/503', [], ['Idempotency-Key' => '"tx-key-0000000000002"'])->assertStatus(503);

    expect(DB::table('users')->count())->toBe(1)
        ->and(IdempotencyKey::query()->count())->toBe(1);

    // The lease was lost meanwhile: the writes roll back and the client sees 409.
    Route::post('/tx-stolen', static function () {
        DB::table('users')->insert(['name' => 'lost']);
        IdempotencyKey::query()->toBase()->update(['owner_token' => 'someone-else']);

        return response('done', 201);
    })->middleware('sentinel.idempotent');

    $this->postJson('/tx-stolen', [], ['Idempotency-Key' => '"tx-key-0000000000003"'])->assertStatus(409);

    expect(DB::table('users')->where('name', 'lost')->count())->toBe(0);

    Route::post('/tx-throws', static function () {
        DB::table('users')->insert(['name' => 'thrown']);

        throw new RuntimeException('boom');
    })->middleware('sentinel.idempotent');

    $this->withoutExceptionHandling();

    expect(fn () => $this->postJson('/tx-throws', [], ['Idempotency-Key' => '"tx-key-0000000000004"']))->toThrow(RuntimeException::class)
        ->and(DB::table('users')->where('name', 'thrown')->count())->toBe(0);
});

it('sends an Idempotency-Key from the HTTP client', function (): void {
    Http::fake();

    Http::withIdempotencyKey('order-1234567890-abc')->post('https://api.example.com/orders');
    Http::withIdempotencyKey()->post('https://api.example.com/orders');

    $keys = [];
    Http::assertSent(static function ($request) use (&$keys): bool {
        $keys[] = $request->header('Idempotency-Key')[0];

        return true;
    });

    expect($keys[0])->toBe('"order-1234567890-abc"')
        ->and($keys[1])->toMatch('/^"[0-9a-f-]{36}"$/');
});

it('records idempotent runs under the fake with the real semantics', function (): void {
    $fake = Sentinel::fake();

    Sentinel::idempotency()->run('fake:1', 'jobs', static fn (): int => 1);
    Sentinel::idempotency()->run('fake:1', 'jobs', static fn (): int => 2);

    expect(fn () => Sentinel::idempotency()->run('fake:1', 'jobs', static fn (): int => 3, fingerprint: 'other'))->toThrow(IdempotencyKeyReusedException::class)
        ->and(Sentinel::idempotency()->forget('fake:1', 'jobs'))->toBeTrue()
        ->and(IdempotencyKey::query()->count())->toBe(0);

    $fake->assertIdempotentRun('fake:1');
    $fake->assertIdempotentRun('fake:1', replayed: true);
    $fake->assertIdempotentRun('fake:1', replayed: false);

    expect(fn () => $fake->assertIdempotentRun('other'))->toThrow(ExpectationFailedException::class, 'key [other]');

    // The middleware runs against the fake's in-memory store too.
    Route::post('/faked', static fn (Request $request) => response('ok', 201))->middleware('sentinel.idempotent');
    $this->postJson('/faked', [], ['Idempotency-Key' => '"faked-key-0000000001"'])->assertCreated();
    $this->postJson('/faked', [], ['Idempotency-Key' => '"faked-key-0000000001"'])->assertHeader('Idempotent-Replayed', 'true');

    expect(IdempotencyKey::query()->count())->toBe(0)
        ->and(fn () => $fake->assertIdempotentRun('nope', replayed: true))->toThrow(ExpectationFailedException::class, 'that replayed');
});

/**
 * D-1: the callback ran — its side effect (a mail, a charge) is done — but its result cannot be
 * stored. The key must not be released: a retry would repeat the side effect. It is completed
 * as unreplayable instead, so a retry is refused (409 unavailable) and the callback runs once.
 */
it('never runs a completed callback again when its result cannot be stored', function (string $store, Closure $result): void {
    match ($store) {
        'cache' => config()->set(['sentinel.idempotency.store' => 'cache', 'sentinel.idempotency.cache_store' => 'array']),
        'fake' => Sentinel::fake(),
        default => null,
    };
    $runs = 0;
    $mail = static function () use (&$runs, $result): mixed {
        $runs++;

        return $result();
    };

    expect(fn () => Sentinel::idempotency()->run('invoice-mail:42', 'billing', $mail))->toThrow(IdempotentResultException::class)
        ->and(fn () => Sentinel::idempotency()->run('invoice-mail:42', 'billing', $mail))->toThrow(IdempotentResponseUnavailableException::class)
        ->and($runs)->toBe(1);
})->with(['database', 'cache', 'fake'])->with([
    'binary string' => [static fn (): string => "%PDF-1.7\xB5\xED\xAE\xFB"],
    'infinity' => [static fn (): float => INF],
    'a resource' => [static fn (): mixed => fopen('php://memory', 'r')],
    'too deep' => [static fn (): array => array_reduce(range(1, 600), static fn (array $carry): array => [$carry], [])],
    'a serializer that throws' => [static fn (): JsonSerializable => new class implements JsonSerializable
    {
        public function jsonSerialize(): mixed
        {
            throw new RuntimeException('cannot serialize');
        }
    }],
]);
