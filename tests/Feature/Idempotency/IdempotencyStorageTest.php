<?php

declare(strict_types=1);

use Illuminate\Encryption\Encrypter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyScopeResolver;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;
use RoundlyConsulting\Sentinel\Idempotency\ResponseVault;
use RoundlyConsulting\Sentinel\Idempotency\Stores\CacheIdempotencyStore;
use RoundlyConsulting\Sentinel\Idempotency\Stores\DatabaseIdempotencyStore;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\SentinelServiceProvider;
use RoundlyConsulting\Sentinel\Testing\InMemoryIdempotencyStore;
use RoundlyConsulting\Testing\Database\DriverMatrix;
use RoundlyConsulting\Testing\Fixtures\LockRecorder;
use RoundlyConsulting\Testing\Fixtures\LockRecordingGrammar;

function idempotentRequest(string $key = 'k', string $fingerprint = 'fp', int $ttl = 3600): IdempotentRequest
{
    return new IdempotentRequest('digest-'.$key, 'scope', $fingerprint, $ttl);
}

/**
 * @return array<string, array{0: Closure(): IdempotencyStore}>
 */
function idempotencyStores(): array
{
    return [
        'database' => [static fn (): IdempotencyStore => app(DatabaseIdempotencyStore::class)],
        'cache' => [static fn (): IdempotencyStore => new CacheIdempotencyStore(cache()->store('array'), app(ResponseVault::class), app('log'))],
        'in-memory (the fake)' => [static fn (): IdempotencyStore => new InMemoryIdempotencyStore],
    ];
}

/**
 * §10 item 42: stored responses are encrypted at rest.
 */
it('encrypts stored responses and still replays them after an APP_KEY rotation', function (): void {
    Route::post('/pay', static fn () => response()->json(['card' => '4111-1111'], 201))->middleware('sentinel.idempotent');
    $this->postJson('/pay', [], ['Idempotency-Key' => '"key-0123456789abcdef"'])->assertCreated();

    $stored = (string) IdempotencyKey::query()->value('response');

    expect($stored)->not->toContain('4111-1111')->not->toStartWith('{');

    // Rotate APP_KEY, keeping the old one as a previous key.
    $old = config('app.key');
    config()->set('app.key', 'base64:'.base64_encode(Encrypter::generateKey('aes-256-cbc')));
    config()->set('app.previous_keys', [$old]);
    app()->forgetInstance('encrypter');

    $this->postJson('/pay', [], ['Idempotency-Key' => '"key-0123456789abcdef"'])->assertCreated()->assertJson(['card' => '4111-1111'])->assertHeader('Idempotent-Replayed', 'true');

    // Without the previous key the response cannot be opened: unavailable, never a guess.
    config()->set('app.previous_keys', []);
    app()->forgetInstance('encrypter');

    $this->postJson('/pay', [], ['Idempotency-Key' => '"key-0123456789abcdef"'])->assertStatus(409);
});

it('stores plaintext JSON when encryption is off', function (): void {
    config()->set('sentinel.idempotency.encrypt', 'false');
    Route::post('/plain', static fn () => response()->json(['ok' => true]))->middleware('sentinel.idempotent');

    $this->postJson('/plain', [], ['Idempotency-Key' => '"key-0123456789abcdef"']);

    expect((string) IdempotencyKey::query()->value('response'))->toStartWith('{"v":1');
});

/**
 * §10 item 45: every store follows the same decision table.
 */
it('decides the same way in every store', function (Closure $make): void {
    $store = $make();
    $first = $store->begin(idempotentRequest());

    expect($first->outcome)->toBe(IdempotencyOutcome::Proceed)
        ->and($store->begin(idempotentRequest())->outcome)->toBe(IdempotencyOutcome::InProgress)
        ->and($store->begin(idempotentRequest(fingerprint: 'other'))->outcome)->toBe(IdempotencyOutcome::Reused)
        ->and($store->complete(idempotentRequest(), new ResponseSnapshot(201, [], 'x')))->toBeFalse()
        ->and($store->complete(idempotentRequest()->ownedBy('not-the-owner'), new ResponseSnapshot(201, [], 'x')))->toBeFalse()
        ->and($store->complete(idempotentRequest()->ownedBy((string) $first->ownerToken), new ResponseSnapshot(201, ['etag' => ['"a"']], "bin\xff")))->toBeTrue();

    $replay = $store->begin(idempotentRequest());

    expect($replay->outcome)->toBe(IdempotencyOutcome::Replay)
        ->and($replay->replay?->status)->toBe(201)
        ->and($replay->replay?->body)->toBe("bin\xff")
        ->and($replay->replay?->headers)->toBe(['etag' => ['"a"']]);

    // Unreplayable, released, forgotten.
    $other = $store->begin(idempotentRequest('u'));
    $store->complete(idempotentRequest('u')->ownedBy((string) $other->ownerToken), new ResponseSnapshot(200, [], '', false));
    $released = $store->begin(idempotentRequest('r'));
    $store->release(idempotentRequest('r')->ownedBy('not-the-owner'));

    expect($store->begin(idempotentRequest('u'))->outcome)->toBe(IdempotencyOutcome::Unavailable)
        ->and($store->begin(idempotentRequest('r'))->outcome)->toBe(IdempotencyOutcome::InProgress);

    $store->release(idempotentRequest('r')->ownedBy((string) $released->ownerToken));

    expect($store->begin(idempotentRequest('r'))->outcome)->toBe(IdempotencyOutcome::Proceed)
        ->and($store->forget('digest-k'))->toBeTrue()
        ->and($store->forget('digest-k'))->toBeFalse()
        ->and($store->begin(idempotentRequest())->outcome)->toBe(IdempotencyOutcome::Proceed);
})->with(idempotencyStores());

it('takes an expired lease over and reuses an expired key in every store', function (Closure $make): void {
    $store = $make();
    $this->travelTo('2026-10-02 12:00:00');
    $store->begin(idempotentRequest(ttl: 120));

    $this->travel(61)->seconds();
    $takeover = $store->begin(idempotentRequest(ttl: 120));

    expect($takeover->outcome)->toBe(IdempotencyOutcome::Proceed)
        ->and($takeover->firstSeenAt?->format('H:i:s'))->toBe('10:00:00');

    $this->travel(60)->seconds();
    $fresh = $store->begin(idempotentRequest(fingerprint: 'new payload', ttl: 120));

    expect($fresh->outcome)->toBe(IdempotencyOutcome::Proceed)
        ->and($fresh->firstSeenAt?->format('H:i:s'))->toBe('10:02:01')
        ->and($store->prune(now()->toImmutable()->addDay()))->toBeGreaterThanOrEqual(0);
})->with(idempotencyStores());

it('refuses a cache store without atomic locks', function (): void {
    config()->set('cache.stores.nolock', ['driver' => 'null']);
    config()->set('sentinel.idempotency.store', 'cache');
    config()->set('sentinel.idempotency.cache_store', 'nolock');

    expect(fn () => app(IdempotencyStore::class))->toThrow(InvalidSentinelConfigurationException::class, 'atomic locks')
        ->and(fn () => app()->getProvider(SentinelServiceProvider::class)?->boot())->toThrow(InvalidSentinelConfigurationException::class);

    config()->set('sentinel.idempotency.store', 'memcached-cluster');

    expect(fn () => app(IdempotencyStore::class))->toThrow(InvalidSentinelConfigurationException::class, 'bind');
});

it('fails closed on an edited database record', function (): void {
    $store = app(DatabaseIdempotencyStore::class);
    $store->begin(idempotentRequest());

    if (! corrupt(static fn () => IdempotencyKey::query()->toBase()->update(['locked_until' => '2026-13-45 99:99:99']))) {
        return;
    }

    expect($store->begin(idempotentRequest())->outcome)->toBe(IdempotencyOutcome::Unavailable);
});

it('fails closed on an edited cache entry, like the database store', function (mixed $edited): void {
    $store = new CacheIdempotencyStore(cache()->store('array'), app(ResponseVault::class), app('log'));
    $owner = $store->begin(idempotentRequest());
    cache()->store('array')->put('sentinel:idem:digest-k', $edited, 3600);

    $owned = new IdempotentRequest('digest-k', 'scope', 'fp', 3600, $owner->ownerToken);

    // Never run the handler twice on a guess; the owner can no longer complete or release it.
    expect($store->begin(idempotentRequest())->outcome)->toBe(IdempotencyOutcome::Unavailable)
        ->and($store->complete($owned, new ResponseSnapshot(201, [], 'created', true)))->toBeFalse();

    $store->release($owned);

    expect(cache()->store('array')->get('sentinel:idem:digest-k'))->toBe($edited);
})->with([
    'garbled lease' => [['scope' => 'scope', 'fingerprint' => 'fp', 'owner_token' => 't', 'locked_until' => '2026-13-45 99:99:99', 'expires_at' => '2030-01-01 00:00:00.000000', 'created_at' => '2026-01-01 00:00:00.000000']],
    'no expiry' => [['scope' => 'scope', 'fingerprint' => 'fp', 'owner_token' => 't', 'locked_until' => '2026-01-01 00:00:00.000000', 'created_at' => '2026-01-01 00:00:00.000000']],
    'not a record' => ['completed'],
]);

it('counts expired keys and keeps the rest', function (): void {
    IdempotencyKey::factory()->count(2)->expired()->create();
    IdempotencyKey::factory()->completed()->create();
    $store = app(DatabaseIdempotencyStore::class);

    expect($store->countExpired(now()->toImmutable()))->toBe(2)
        ->and($store->prune(now()->toImmutable()))->toBe(2)
        ->and(IdempotencyKey::query()->count())->toBe(1)
        ->and((new IdempotencyKey)->getHidden())->toBe(['response', 'owner_token']);
});

it('round-trips response snapshots strictly', function (): void {
    $snapshot = ResponseSnapshot::fromJson((new ResponseSnapshot(200, ['x' => ['1']], 'body'))->toJson());

    expect($snapshot->body)->toBe('body')
        ->and(ResponseSnapshot::forValue(['a' => 1.0])->value())->toBe(['a' => 1.0]);

    foreach (['nope', '{"v":2}', '{"v":1,"status":200,"headers":{"x":"y"},"body":""}', '{"v":1,"status":200,"headers":{},"body":"%%","encoding":"base64"}'] as $broken) {
        expect(fn () => ResponseSnapshot::fromJson($broken))->toThrow(CorruptRecordException::class);
    }

    expect(fn () => (new ResponseSnapshot(200, [], 'not json'))->value())->toThrow(CorruptRecordException::class);
});

it('keeps the scope apart for signature-less anonymous clients by IP', function (): void {
    $resolver = app(IdempotencyScopeResolver::class);

    expect($resolver->resolve(Request::create('/', 'POST', server: ['REMOTE_ADDR' => '10.0.0.7'])))->toBe('ip:10.0.0.7');
});

it('decides a taken key under its row lock', function (): void {
    $store = app(DatabaseIdempotencyStore::class);
    $store->begin(idempotentRequest());
    $connection = DB::connection();
    $connection->setQueryGrammar(new LockRecordingGrammar($connection));
    LockRecorder::flush();
    LockRecorder::listenForMarkers();

    $store->begin(idempotentRequest());

    $locks = LockRecorder::recorded();

    expect($locks)->toHaveCount(1)
        ->and($locks[0]['sql'])->toContain('sentinel_idempotency_keys')
        ->and($locks[0]['transactionDepth'])->toBe(1);
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'the recording grammar is SQLite-only; the real-engine legs lock for real');
