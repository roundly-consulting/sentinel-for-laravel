<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Enums\HealthStatus;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;
use RoundlyConsulting\Sentinel\Idempotency\ResponseVault;
use RoundlyConsulting\Sentinel\Idempotency\Stores\CacheIdempotencyStore;
use RoundlyConsulting\Sentinel\Idempotency\Stores\DatabaseIdempotencyStore;
use RoundlyConsulting\Sentinel\Jobs\Middleware\Idempotent;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Testing\InMemoryIdempotencyStore;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * Idempotency defects found by the dual review.
 */
it('never replays another row\'s encrypted response (dual-review O-11)', function (): void {
    Route::post('/tokens', static fn (Request $request) => response()->json([
        'owner' => $request->user()?->getAuthIdentifier(),
        'secret' => 'tok_'.bin2hex(random_bytes(8)),
    ], 201))->middleware('sentinel.idempotent');

    $victim = User::query()->create(['name' => 'victim']);
    $attacker = User::query()->create(['name' => 'attacker']);
    $this->actingAs($victim)->postJson('/tokens', [], ['Idempotency-Key' => '"victim-key-0000000000001"'])->assertCreated();
    $this->actingAs($attacker)->postJson('/tokens', [], ['Idempotency-Key' => '"attacker-key-00000000001"'])->assertCreated();

    $rows = IdempotencyKey::query()->orderBy('id')->get();
    // A DB writer copies the victim's ciphertext into its own row, then retries its own key.
    IdempotencyKey::query()->whereKey($rows[1]->id)->toBase()->update(['response' => $rows[0]->getRawOriginal('response')]);

    $replay = $this->actingAs($attacker)->postJson('/tokens', [], ['Idempotency-Key' => '"attacker-key-00000000001"']);

    expect($replay->getStatusCode())->toBe(409)
        ->and($replay->json('secret'))->toBeNull();
});

it('never replays a planted plaintext or application-encrypted response while encryption is on (dual-review O-11)', function (string $planted): void {
    Route::post('/orders', static fn () => response()->json(['ok' => true], 201))->middleware('sentinel.idempotent');
    $user = User::query()->create(['name' => 'u']);
    $this->actingAs($user)->postJson('/orders', [], ['Idempotency-Key' => '"order-key-000000000001"'])->assertCreated();
    $forged = json_encode(['v' => 1, 'status' => 302, 'headers' => ['location' => ['https://evil.example/phish']], 'encoding' => 'utf8', 'body' => ''], JSON_THROW_ON_ERROR);

    IdempotencyKey::query()->toBase()->update(['response' => $planted === 'plaintext' ? $forged : Crypt::encryptString($forged)]);

    $replay = $this->actingAs($user)->postJson('/orders', [], ['Idempotency-Key' => '"order-key-000000000001"']);

    expect($replay->getStatusCode())->toBe(409)
        ->and($replay->headers->get('location'))->toBeNull();
})->with(['plaintext', 'app encrypter']);

it('binds a cached response to its key, too (dual-review O-11)', function (): void {
    $store = new CacheIdempotencyStore(cache()->store('array'), app(ResponseVault::class), app('log'));
    $a = new IdempotentRequest('digest-a', 'scope', 'fp', 3600);
    $b = new IdempotentRequest('digest-b', 'scope', 'fp', 3600);
    $snapshot = new ResponseSnapshot(201, ['content-type' => ['application/json']], '{"secret":"a"}');

    $store->complete($a->ownedBy((string) $store->begin($a)->ownerToken), $snapshot);
    $store->complete($b->ownedBy((string) $store->begin($b)->ownerToken), new ResponseSnapshot(201, [], '{"secret":"b"}'));

    $entry = cache()->store('array')->get('sentinel:idem:digest-a');
    cache()->store('array')->put('sentinel:idem:digest-b', [...cache()->store('array')->get('sentinel:idem:digest-b'), 'response' => $entry['response']], 3600);

    expect($store->begin($a)->outcome)->toBe(IdempotencyOutcome::Replay)
        ->and($store->begin($b)->outcome)->toBe(IdempotencyOutcome::Unavailable);
});

it('still replays its own plaintext and encrypted responses when encryption is off (dual-review O-11)', function (): void {
    $vault = app(ResponseVault::class);
    $request = new IdempotentRequest('digest-k', 'scope', 'fp', 3600);
    $snapshot = new ResponseSnapshot(200, [], 'ok');
    $encrypted = $vault->seal($snapshot, $request, 'database');

    config()->set('sentinel.idempotency.encrypt', 'false');
    $plain = $vault->seal($snapshot, $request, 'database');

    expect($plain)->toStartWith('{')
        ->and($vault->open($plain, $request, 'database')?->body)->toBe('ok')
        ->and($vault->open($encrypted, $request, 'database')?->body)->toBe('ok')
        ->and($vault->open($encrypted, $request, 'cache'))->toBeNull()
        ->and($vault->open('not json', $request, 'database'))->toBeNull();
});

it('stores and replays a response whose replayed header is not UTF-8 (dual-review O-12)', function (): void {
    config()->set('app.debug', false);
    $runs = 0;
    $etag = '"'.hash('sha256', 'file', true).'"';
    Route::post('/files', static function () use (&$runs, $etag) {
        $runs++;

        return response()->json(['stored' => $runs], 201)->header('ETag', $etag);
    })->middleware('sentinel.idempotent');
    $user = User::query()->create(['name' => 'u']);

    $first = $this->actingAs($user)->postJson('/files', [], ['Idempotency-Key' => '"file-key-0000000000001"']);
    $this->travel(61)->seconds();
    $retry = $this->actingAs($user)->postJson('/files', [], ['Idempotency-Key' => '"file-key-0000000000001"']);

    expect($first->getStatusCode())->toBe(201)
        ->and(IdempotencyKey::query()->value('status'))->toBe('completed')
        ->and($retry->getStatusCode())->toBe(201)
        ->and($retry->headers->get('Idempotent-Replayed'))->toBe('true')
        ->and($retry->headers->get('ETag'))->toBe($etag)
        ->and($runs)->toBe(1);
});

it('completes the key as unreplayable when the response cannot be stored after the handler ran (dual-review O-12)', function (): void {
    config()->set('app.debug', false);
    $runs = 0;
    Route::post('/charges', static function () use (&$runs) {
        $runs++;
        // The response cannot be encrypted at rest: the handler has run all the same.
        config()->set('app.key', '');

        return response()->json(['charged' => true], 201);
    })->middleware('sentinel.idempotent');
    $user = User::query()->create(['name' => 'u']);
    $key = config('app.key');

    $first = $this->actingAs($user)->postJson('/charges', [], ['Idempotency-Key' => '"charge-key-0000000000001"']);
    config()->set('app.key', $key);
    $retry = $this->actingAs($user)->postJson('/charges', [], ['Idempotency-Key' => '"charge-key-0000000000001"']);

    expect($first->getStatusCode())->toBe(201)
        ->and(IdempotencyKey::query()->value('status'))->toBe('completed')
        ->and(IdempotencyKey::query()->value('replayable'))->toBeFalsy()
        ->and($retry->getStatusCode())->toBe(409)
        ->and($runs)->toBe(1);
});

it('never lets a key\'s TTL end a live lease (dual-review O-27)', function (): void {
    config()->set('sentinel.idempotency.lock_seconds', 600);
    $runs = 0;
    $refused = 0;

    Sentinel::idempotency()->run('export-42-abcdef', 'exports', function () use (&$runs, &$refused): null {
        $runs++;
        $this->travel(61)->seconds();

        try {
            Sentinel::idempotency()->run('export-42-abcdef', 'exports', static function () use (&$runs): null {
                $runs++;

                return null;
            }, ttl: 60);
        } catch (IdempotencyRequestInProgressException) {
            $refused++;
        }

        return null;
    }, ttl: 60);

    expect($runs)->toBe(1)
        ->and($refused)->toBe(1);
});

it('never prunes, nor lets the cache drop, a key whose lease is live (dual-review O-27)', function (Closure $make): void {
    config()->set('sentinel.idempotency.lock_seconds', 600);
    /** @var IdempotencyStore $store */
    $store = $make();
    $request = new IdempotentRequest('digest-live', 'scope', 'fp', 60);
    $owner = $store->begin($request);

    $this->travel(61)->seconds();

    expect($store->prune(Clock::now()))->toBe(0)
        ->and($store->begin($request)->outcome)->toBe(IdempotencyOutcome::InProgress)
        ->and($store->complete($request->ownedBy((string) $owner->ownerToken), new ResponseSnapshot(200, [], 'done')))->toBeTrue();

    $this->travel(600)->seconds();

    // Completed and past its TTL: it goes, and the key is fresh again.
    expect($store->prune(Clock::now()))->toBe($store instanceof CacheIdempotencyStore ? 0 : 1)
        ->and($store->begin($request)->outcome)->toBe(IdempotencyOutcome::Proceed);
})->with([
    'database' => [static fn (): IdempotencyStore => app(DatabaseIdempotencyStore::class)],
    'cache' => [static fn (): IdempotencyStore => new CacheIdempotencyStore(cache()->store('array'), app(ResponseVault::class), app('log'))],
    'in-memory (the fake)' => [static fn (): IdempotencyStore => new InMemoryIdempotencyStore],
]);

/**
 * A job double: its middleware releases a duplicate back onto the queue.
 */
function releasableJob(?int $timeout = null, ?string $connection = null): object
{
    return new class($timeout, $connection)
    {
        /** @var list<int> */
        public array $released = [];

        public function __construct(public ?int $timeout, public ?string $connection) {}

        public function release(int $delay = 0): void
        {
            $this->released[] = $delay;
        }
    };
}

it('never runs a duplicate job beside one that outlives lock_seconds (dual-review O-13)', function (Closure $middleware, Closure $job): void {
    $runs = 0;
    $first = $job();
    $duplicate = $job();
    $middleware = $middleware();

    $middleware->handle($first, function () use (&$runs, $middleware, $duplicate): void {
        $runs++;
        // The first run is slow; 61 s in the queue redelivers the job.
        $this->travel(61)->seconds();

        $middleware->handle($duplicate, function () use (&$runs): void {
            $runs++;
        });
    });

    expect($runs)->toBe(1)
        ->and($duplicate->released)->not->toBe([]);
})->with([
    'an explicit lease' => [static fn (): Idempotent => new Idempotent('stripe:evt_long', scope: 'webhooks', lease: 600), static fn (): object => releasableJob()],
    'the job\'s own timeout' => [static fn (): Idempotent => new Idempotent('stripe:evt_long', scope: 'webhooks'), static fn (): object => releasableJob(timeout: 300)],
    'the queue\'s retry_after' => [static function (): Idempotent {
        config()->set('queue.connections.slow', ['driver' => 'database', 'retry_after' => 900]);

        return new Idempotent('stripe:evt_long', scope: 'webhooks');
    }, static fn (): object => releasableJob(connection: 'slow')],
]);

it('holds a run() key for its lease (dual-review O-13)', function (): void {
    $runs = 0;

    Sentinel::idempotency()->run('export-77-abcdef', 'exports', function () use (&$runs): null {
        $runs++;
        $this->travel(601)->seconds();

        expect(fn () => Sentinel::idempotency()->run('export-77-abcdef', 'exports', static fn () => null, lease: 1200))->toThrow(IdempotencyRequestInProgressException::class);

        return null;
    }, lease: 1200);

    expect($runs)->toBe(1)
        ->and(fn () => new Idempotent('k', lease: 0))->toThrow(InvalidIdempotencyKeyException::class)
        ->and(fn () => Sentinel::idempotency()->run('k', 's', static fn () => 1, lease: 86401))->toThrow(InvalidIdempotencyKeyException::class);
});

it('refuses the transactional mode with a store the transaction cannot roll back (dual-review O-26)', function (): void {
    config()->set('sentinel.idempotency.transactional', true);
    config()->set('sentinel.idempotency.store', 'cache');

    expect(fn () => Settings::idempotencyTransactional())->toThrow(InvalidSentinelConfigurationException::class, 'idempotency.transactional')
        ->and(Sentinel::check()->get('configuration')?->status)->toBe(HealthStatus::Failure);

    config()->set('sentinel.idempotency.store', 'database');

    expect(Settings::idempotencyTransactional())->toBeTrue();
});

it('never replays a response whose transaction failed to commit (dual-review O-26)', function (): void {
    $db = DB::connection();

    if ($db->getDriverName() !== 'pgsql') {
        $this->markTestSkipped('needs a deferred constraint that fails at COMMIT (PostgreSQL)');
    }

    config()->set('sentinel.idempotency.transactional', true);
    $db->statement('CREATE TABLE review_parents (id integer primary key)');
    $db->statement('CREATE TABLE review_children (id serial primary key, parent_id integer REFERENCES review_parents(id) DEFERRABLE INITIALLY DEFERRED)');
    Route::post('/charge', static function () use ($db) {
        $db->table('review_children')->insert(['parent_id' => 999]);

        return response()->json(['charged' => true], 201);
    })->middleware('sentinel.idempotent');
    $user = User::query()->create(['name' => 'u']);

    $first = $this->actingAs($user)->postJson('/charge', [], ['Idempotency-Key' => '"charge-key-00000000001"']);
    $retry = $this->actingAs($user)->postJson('/charge', [], ['Idempotency-Key' => '"charge-key-00000000001"']);

    expect($first->getStatusCode())->toBe(500)
        ->and($db->table('review_children')->count())->toBe(0)
        ->and($retry->headers->get('Idempotent-Replayed'))->toBeNull();
});
