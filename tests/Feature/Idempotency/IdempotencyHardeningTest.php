<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentRequest;
use RoundlyConsulting\Sentinel\Enums\IdempotencyOutcome;
use RoundlyConsulting\Sentinel\Idempotency\ResponseSnapshot;
use RoundlyConsulting\Sentinel\Idempotency\ResponseVault;
use RoundlyConsulting\Sentinel\Idempotency\Stores\CacheIdempotencyStore;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
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
