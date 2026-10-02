<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Enums\NonceKind;
use RoundlyConsulting\Sentinel\Exceptions\InvalidPurposeException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\NonceRejectedException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Nonce;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\Nonces\Stores\CacheNonceStore;
use RoundlyConsulting\Sentinel\Nonces\Stores\DatabaseNonceStore;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\InMemoryNonceStore;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * @return array<string, array{0: Closure(): NonceStore}>
 */
function nonceStores(): array
{
    return [
        'database' => [static fn (): NonceStore => new DatabaseNonceStore],
        'cache' => [static fn (): NonceStore => new CacheNonceStore(cache()->store('array'))],
        'in-memory (the fake)' => [static fn (): NonceStore => new InMemoryNonceStore],
    ];
}

/**
 * §10 item 46: issue and consume.
 */
it('consumes a nonce exactly once, and stores only its digest', function (): void {
    $user = User::query()->create(['name' => 'u']);
    $nonce = Sentinel::nonces()->issue('password-reset', subject: $user);

    expect($nonce->value)->toHaveLength(43)
        ->and($nonce->purpose)->toBe('password-reset')
        ->and(Nonce::query()->value('digest'))->toBe(NonceDigest::of($nonce->value))
        ->and(Nonce::query()->firstOrFail()->kind)->toBe(NonceKind::Issued)
        ->and(Nonce::query()->firstOrFail()->subject?->is($user))->toBeTrue()
        ->and(json_encode(Nonce::query()->get()))->not->toContain($nonce->value)
        ->and(print_r($nonce, true))->not->toContain($nonce->value)
        ->and(fn () => serialize($nonce))->toThrow(LogicException::class)
        ->and(Sentinel::nonces()->consume('password-reset', $nonce->value, $user))->toBeTrue()
        ->and(Sentinel::nonces()->consume('password-reset', $nonce->value, $user))->toBeFalse();
});

it('refuses wrong purposes, subjects, expired, used and unknown nonces alike', function (Closure $make): void {
    $store = $make();
    $alice = User::query()->create(['name' => 'alice']);
    $bob = User::query()->create(['name' => 'bob']);
    $now = now()->toImmutable();

    $store->issue('login', 'd1', $now->addMinute(), $alice);
    $store->issue('login', 'd2', $now->subSecond(), null);
    $store->issue('login', 'd3', $now->addMinute(), null);

    expect($store->consume('signup', 'd1', $now, $alice))->toBeFalse()
        ->and($store->consume('login', 'd1', $now, $bob))->toBeFalse()
        ->and($store->consume('login', 'd1', $now, null))->toBeFalse()
        ->and($store->consume('login', 'd2', $now, null))->toBeFalse()
        ->and($store->consume('login', 'unknown', $now, null))->toBeFalse()
        ->and($store->consume('login', 'd3', $now, $alice))->toBeFalse()
        ->and($store->consume('login', 'd1', $now, $alice))->toBeTrue()
        ->and($store->consume('login', 'd1', $now, $alice))->toBeFalse()
        ->and($store->consume('login', 'd3', $now, null))->toBeTrue();
})->with(nonceStores());

/**
 * §10 item 47: remembering nonces a client sent.
 */
it('remembers a client nonce until its window ends', function (Closure $make): void {
    $store = $make();
    $now = now()->toImmutable();

    expect($store->remember('http:x', 'n1', $now->addSeconds(10), $now))->toBeTrue()
        ->and($store->remember('http:x', 'n1', $now->addSeconds(10), $now->addSeconds(5)))->toBeFalse()
        ->and($store->remember('http:y', 'n1', $now->addSeconds(10), $now))->toBeTrue();

    $this->travel(11)->seconds();

    expect($store->remember('http:x', 'n1', now()->toImmutable()->addSeconds(10), now()->toImmutable()))->toBeTrue()
        ->and($store->prune(now()->toImmutable()->addDay()))->toBeGreaterThanOrEqual(0);
})->with(nonceStores());

it('consumes or throws a 403 problem', function (): void {
    $nonce = Sentinel::nonces()->issue('invite', ttl: 60);

    Sentinel::nonces()->consumeOrFail('invite', $nonce->value);

    try {
        Sentinel::nonces()->consumeOrFail('invite', $nonce->value);
        $this->fail('The nonce was accepted twice.');
    } catch (NonceRejectedException $exception) {
        expect($exception->getStatusCode())->toBe(403)
            ->and($exception->toResponse(request())->getStatusCode())->toBe(403)
            ->and($exception->toResponse(request())->getData(true))->toMatchArray(['code' => 'nonce_rejected', 'status' => 403]);
    }
});

it('validates purposes, lifetimes and values', function (): void {
    expect(fn () => Sentinel::nonces()->issue('Bad Purpose'))->toThrow(InvalidPurposeException::class)
        ->and(fn () => Sentinel::nonces()->consume('Bad Purpose', 'x'))->toThrow(InvalidPurposeException::class)
        ->and(fn () => Sentinel::nonces()->issue('ok', ttl: 0))->toThrow(InvalidSentinelConfigurationException::class)
        ->and(Sentinel::nonces()->consume('ok', ''))->toBeFalse()
        ->and(Sentinel::nonces()->consume('ok', str_repeat('n', 513)))->toBeFalse();

    config()->set('sentinel.nonces.length', 64);

    expect(Sentinel::nonces()->issue('ok')->value)->toHaveLength(64);
});

it('expires nonces after their TTL and prunes them', function (): void {
    $nonce = Sentinel::nonces()->issue('short', ttl: 30);
    Nonce::factory()->seen()->expired()->create();

    $this->travel(31)->seconds();

    expect(Sentinel::nonces()->consume('short', $nonce->value))->toBeFalse()
        ->and(Artisan::call('sentinel:prune', ['--nonces' => true, '--dry-run' => true]))->toBe(0)
        ->and(Artisan::output())->toContain('Would delete nonces')->toContain('2')
        ->and(Nonce::query()->count())->toBe(2)
        ->and(app(SentinelManager::class)->prune()->nonces)->toBe(2)
        ->and(Nonce::query()->count())->toBe(0);
});

/**
 * §10 item 48: single-use signed URLs.
 */
it('opens a single-use URL exactly once', function (): void {
    Route::get('/exports/{export}', static fn (string $export): string => 'export '.$export)->name('exports.download')->middleware('sentinel.single-use');
    Route::get('/other/{export}', static fn (): string => 'other')->name('other')->middleware('sentinel.single-use');
    config()->set('app.debug', false);

    $url = Sentinel::nonces()->signedRoute('exports.download', ['export' => 7], 600);

    $this->get($url)->assertOk()->assertSee('export 7');
    $this->get($url)->assertForbidden()->assertJson(['code' => 'nonce_rejected']);

    // A tampered signature is refused before the nonce is touched.
    $fresh = Sentinel::nonces()->signedRoute('exports.download', ['export' => 8]);
    $this->get(str_replace('exports/8', 'exports/9', $fresh))->assertForbidden();
    $this->get($fresh)->assertOk();

    // Expired, and a nonce moved to another route.
    $expiring = Sentinel::nonces()->signedRoute('exports.download', ['export' => 1], 60);
    $this->travel(61)->seconds();
    $this->get($expiring)->assertForbidden();

    $nonce = Sentinel::nonces()->issue('url:exports.download');
    $this->get(URL::temporarySignedRoute('other', now()->addMinute(), ['export' => 1, '_nonce' => $nonce->value]))->assertForbidden();
    $this->get(URL::signedRoute('other', ['export' => 1]))->assertForbidden();
});

it('derives a purpose for any route name', function (): void {
    expect(NonceDigest::routePurpose('exports.download'))->toBe('url:exports.download')
        ->and(NonceDigest::routePurpose('Exports Download'))->toStartWith('url:h.');
});

it('records nonces under the fake and keeps their real semantics', function (): void {
    Route::get('/fake/{id}', static fn (): string => 'ok')->name('fake.link')->middleware('sentinel.single-use');
    $fake = Sentinel::fake();

    $nonce = Sentinel::nonces()->issue('fake-purpose');

    expect(Sentinel::nonces()->consume('fake-purpose', $nonce->value))->toBeTrue()
        ->and(Sentinel::nonces()->consume('fake-purpose', $nonce->value))->toBeFalse()
        ->and(Nonce::query()->count())->toBe(0)
        ->and(Sentinel::prune()->nonces)->toBe(0);

    $url = Sentinel::nonces()->signedRoute('fake.link', ['id' => 1]);
    $this->get($url)->assertOk();
    $this->get($url)->assertForbidden();

    $fake->assertNonceIssued('fake-purpose');
    $fake->assertNonceConsumed('fake-purpose');
    $fake->assertNonceConsumed('url:fake.link');

    expect(fn () => $fake->assertNonceIssued('other'))->toThrow(ExpectationFailedException::class, '[other]')
        ->and(fn () => $fake->assertNonceConsumed('other'))->toThrow(ExpectationFailedException::class, '[other]');
});

it('refuses a cache nonce store without atomic locks', function (): void {
    config()->set('cache.stores.nolock', ['driver' => 'null']);
    config()->set('sentinel.nonces.store', 'cache');
    config()->set('sentinel.nonces.cache_store', 'nolock');

    expect(fn () => app(NonceStore::class))->toThrow(InvalidSentinelConfigurationException::class, 'atomic locks');

    config()->set('sentinel.nonces.store', 'custom');

    expect(fn () => app(NonceStore::class))->toThrow(InvalidSentinelConfigurationException::class, 'bind');
});
