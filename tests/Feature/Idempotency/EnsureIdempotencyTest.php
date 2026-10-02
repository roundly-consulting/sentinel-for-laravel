<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\Enums\IdempotencyRejection;
use RoundlyConsulting\Sentinel\Events\IdempotencyRejected;
use RoundlyConsulting\Sentinel\Events\IdempotentRequestReplayed;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Http\Middleware\EnsureIdempotency;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;
use Symfony\Component\HttpFoundation\StreamedResponse;

const IDEMPOTENCY_KEY = '"8e03978e-40d5-43e8-bc93-6894a57f9324"';

function handled(): int
{
    return (int) cache()->get('handled', 0);
}

beforeEach(function (): void {
    config()->set('app.debug', false);

    $handler = static function (Request $request) {
        $count = cache()->increment('handled');

        return response()->json(['order' => $count, 'echo' => $request->input('item')], 201)
            ->header('ETag', '"v'.$count.'"')
            ->header('X-Internal', 'not replayed')
            ->withCookie(cookie('session', 'secret-session'));
    };

    Route::post('/orders', $handler)->middleware('sentinel.idempotent');
    Route::patch('/orders', $handler)->middleware('sentinel.idempotent');
    Route::put('/orders', $handler)->middleware('sentinel.idempotent');
    Route::post('/required', $handler)->middleware('sentinel.idempotent:required');
    Route::post('/short', $handler)->middleware('sentinel.idempotent:optional,60');
    Route::post('/broken', static function () {
        cache()->increment('handled');

        return response('down', 503);
    })->middleware('sentinel.idempotent');
    Route::post('/invalid', static function () {
        cache()->increment('handled');

        return response()->json(['error' => 'nope'], 422);
    })->middleware('sentinel.idempotent');
    Route::post('/stream', static fn () => new StreamedResponse(static function (): void {
        echo 'streamed';
    }))->middleware('sentinel.idempotent');
    Route::post('/big', static fn () => response(str_repeat('x', 2048)))->middleware('sentinel.idempotent');
});

/**
 * §10 item 41: the idempotency state machine over HTTP.
 */
it('replays the stored response to a repeat, without running the handler again', function (): void {
    Event::fake([IdempotentRequestReplayed::class]);

    $first = $this->postJson('/orders', ['item' => 'book'], ['Idempotency-Key' => IDEMPOTENCY_KEY]);
    $second = $this->postJson('/orders', ['item' => 'book'], ['Idempotency-Key' => IDEMPOTENCY_KEY]);

    $first->assertCreated()->assertJson(['order' => 1])->assertHeaderMissing('Idempotent-Replayed');
    $second->assertCreated()->assertJson(['order' => 1, 'echo' => 'book'])
        ->assertHeader('Idempotent-Replayed', 'true')
        ->assertHeader('ETag', '"v1"')
        ->assertHeaderMissing('X-Internal');

    expect(handled())->toBe(1)
        ->and($second->headers->getCookies())->toBe([]);

    Event::assertDispatched(IdempotentRequestReplayed::class, static fn (IdempotentRequestReplayed $event): bool => $event->status === 201 && $event->method === 'POST');
});

it('refuses a key reused with another payload (422)', function (): void {
    Event::fake([IdempotencyRejected::class]);

    $this->postJson('/orders', ['item' => 'book'], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated();
    $reused = $this->postJson('/orders', ['item' => 'pen'], ['Idempotency-Key' => IDEMPOTENCY_KEY]);

    $reused->assertStatus(422)
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJson(['status' => 422, 'code' => 'idempotency_key_reused', 'title' => 'Idempotency key reused'])
        ->assertJsonMissingPath('type');

    expect(handled())->toBe(1);

    Event::assertDispatched(IdempotencyRejected::class, static fn (IdempotencyRejected $event): bool => $event->reason === IdempotencyRejection::Reused && $event->status === 422);
});

it('treats other whitespace in the raw body as another payload', function (): void {
    $this->call('POST', '/orders', server: ['HTTP_IDEMPOTENCY_KEY' => IDEMPOTENCY_KEY, 'CONTENT_TYPE' => 'application/json'], content: '{"item":"book"}')->assertCreated();

    $this->call('POST', '/orders', server: ['HTTP_IDEMPOTENCY_KEY' => IDEMPOTENCY_KEY, 'CONTENT_TYPE' => 'application/json'], content: '{"item": "book"}')->assertStatus(422);
});

it('answers 409 with Retry-After while the first request still runs, and takes over an expired lease', function (): void {
    $this->travelTo('2026-10-02 12:00:00');
    $this->postJson('/orders', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated();

    // As if that request still held the key (its lease runs until 10:00:30 UTC).
    IdempotencyKey::query()->toBase()->update(['status' => IdempotencyKey::PROCESSING, 'locked_until' => '2026-10-02 10:00:30.000000']);

    $this->travelTo('2026-10-02 12:00:10');
    $this->postJson('/orders', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])
        ->assertStatus(409)
        ->assertHeader('Retry-After', '20')
        ->assertJson(['code' => 'idempotency_request_in_progress']);

    $this->travelTo('2026-10-02 12:00:31');
    $this->postJson('/orders', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated()->assertJson(['order' => 2]);
});

it('releases the key on a server error so the client may retry', function (): void {
    $this->postJson('/broken', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertStatus(503);
    $this->postJson('/broken', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertStatus(503);

    expect(handled())->toBe(2)
        ->and(IdempotencyKey::query()->count())->toBe(0);

    config()->set('sentinel.idempotency.store_server_errors', true);
    $this->postJson('/broken', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertStatus(503);
    $this->postJson('/broken', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertStatus(503)->assertHeader('Idempotent-Replayed', 'true');

    expect(handled())->toBe(3);
});

it('stores client errors unless told not to', function (): void {
    $this->postJson('/invalid', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertStatus(422);
    $this->postJson('/invalid', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertStatus(422)->assertHeader('Idempotent-Replayed', 'true');

    expect(handled())->toBe(1);

    config()->set('sentinel.idempotency.store_client_errors', 'no');
    $other = '"9e03978e-40d5-43e8-bc93-6894a57f9324"';
    $this->postJson('/invalid', [], ['Idempotency-Key' => $other])->assertStatus(422);
    $this->postJson('/invalid', [], ['Idempotency-Key' => $other])->assertStatus(422)->assertHeaderMissing('Idempotent-Replayed');

    expect(handled())->toBe(3);
});

it('answers 409 for a completed response it cannot replay', function (string $uri): void {
    config()->set('sentinel.idempotency.max_response_bytes', 1024);

    $this->postJson($uri, [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertOk();

    $this->postJson($uri, [], ['Idempotency-Key' => IDEMPOTENCY_KEY])
        ->assertStatus(409)
        ->assertJson(['code' => 'idempotent_response_unavailable']);
})->with(['streamed' => ['/stream'], 'too large' => ['/big']]);

it('lets a key expire after its TTL', function (): void {
    $this->postJson('/short', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated();
    $this->travel(30)->seconds();
    $this->postJson('/short', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertHeader('Idempotent-Replayed', 'true');
    $this->travel(31)->seconds();
    $this->postJson('/short', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated()->assertJson(['order' => 2]);
});

it('requires a key only where asked to, and only on unsafe methods', function (): void {
    $this->postJson('/orders')->assertCreated();
    $this->postJson('/required')->assertStatus(400)->assertJson(['code' => 'idempotency_key_missing']);
    $this->putJson('/orders', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated();
    $this->putJson('/orders', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated()->assertHeaderMissing('Idempotent-Replayed');
    $this->patchJson('/orders', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertCreated();
    $this->patchJson('/orders', [], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertHeader('Idempotent-Replayed', 'true');
    $this->postJson('/orders', [], ['Idempotency-Key' => '"short"'])->assertStatus(400)->assertJson(['code' => 'invalid_idempotency_key']);
});

it('scopes keys to the user, so users never share or replay each other\'s keys', function (): void {
    $alice = User::query()->create(['name' => 'alice']);
    $bob = User::query()->create(['name' => 'bob']);

    $this->actingAs($alice)->postJson('/orders', ['item' => 'a'], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertJson(['order' => 1]);
    $this->actingAs($bob)->postJson('/orders', ['item' => 'b'], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertJson(['order' => 2])->assertHeaderMissing('Idempotent-Replayed');
    $this->actingAs($alice)->postJson('/orders', ['item' => 'a'], ['Idempotency-Key' => IDEMPOTENCY_KEY])->assertJson(['order' => 1])->assertHeader('Idempotent-Replayed', 'true');
});

it('describes problems with a typed URL when configured', function (): void {
    config()->set('sentinel.problems.type_base', 'https://example.com/problems');

    $this->postJson('/required')->assertJson(['type' => 'https://example.com/problems#idempotency_key_missing']);
});

it('releases the key when the handler throws past the pipeline', function (): void {
    $request = Request::create('/orders', 'POST', server: ['HTTP_IDEMPOTENCY_KEY' => IDEMPOTENCY_KEY]);

    expect(fn () => app(EnsureIdempotency::class)->handle($request, static fn () => throw new RuntimeException('boom')))->toThrow(RuntimeException::class, 'boom')
        ->and(IdempotencyKey::query()->count())->toBe(0)
        ->and(app(EnsureIdempotency::class)->handle($request, static fn (): string => 'plain')->getContent())->toBe('plain');
});

it('refuses a misconfigured middleware', function (string $mode, ?string $ttl): void {
    $request = Request::create('/orders', 'POST', server: ['HTTP_IDEMPOTENCY_KEY' => IDEMPOTENCY_KEY]);

    expect(fn () => app(EnsureIdempotency::class)->handle($request, static fn (): string => 'x', $mode, $ttl))->toThrow(SealingMisconfiguredException::class);
})->with([['always', null], ['optional', '5'], ['optional', 'soon']]);
