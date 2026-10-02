<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Http\Middleware\EnsureIdempotency;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifyHttpSignature;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifySeals;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

/**
 * I-14: typed middleware parameters, validated when the route is declared.
 */
it('builds the middleware strings', function (): void {
    expect(VerifySeals::using())->toBe(VerifySeals::class)
        ->and(VerifySeals::using('invoice@financial', 'customer'))->toBe(VerifySeals::class.':invoice@financial,customer')
        ->and(EnsureIdempotency::optional())->toBe(EnsureIdempotency::class.':optional')
        ->and(EnsureIdempotency::required(ttl: 3600))->toBe(EnsureIdempotency::class.':required,3600')
        ->and(VerifyHttpSignature::profile())->toBe(VerifyHttpSignature::class)
        ->and(VerifyHttpSignature::profile('default'))->toBe(VerifyHttpSignature::class.':default');
});

it('verifies seals exactly like the alias form', function (): void {
    $invoice = invoice();
    Route::get('/typed/{invoice}', static fn (Invoice $invoice): string => 'ok')->middleware([SubstituteBindings::class, VerifySeals::using('invoice@financial')]);
    Route::get('/alias/{invoice}', static fn (Invoice $invoice): string => 'ok')->middleware([SubstituteBindings::class, 'sentinel.verified:invoice@financial']);

    expect($this->get("/typed/{$invoice->id}")->status())->toBe(200);

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);

    expect($this->get("/typed/{$invoice->id}")->status())->toBe(409)
        ->and($this->get("/alias/{$invoice->id}")->status())->toBe(409);
});

it('enforces idempotency keys exactly like the alias form', function (): void {
    Route::post('/typed/orders', static fn (): array => ['id' => random_int(1, PHP_INT_MAX)])->middleware(EnsureIdempotency::required(ttl: 3600));
    Route::post('/optional/orders', static fn (): array => ['ok' => true])->middleware(EnsureIdempotency::optional());
    $key = ['Idempotency-Key' => '"0b9c4f5e-1a2b-4c3d-8e9f-0a1b2c3d4e5f"'];

    $first = $this->postJson('/typed/orders', [], $key);
    $second = $this->postJson('/typed/orders', [], $key);

    expect($this->postJson('/typed/orders')->status())->toBe(400)
        ->and($second->json('id'))->toBe($first->json('id'))
        ->and($second->headers->get('Idempotent-Replayed'))->toBe('true')
        ->and($this->postJson('/optional/orders')->status())->toBe(200)
        ->and(IdempotencyKey::query()->firstOrFail()->expires_at->diffInSeconds(IdempotencyKey::query()->firstOrFail()->created_at, true))->toBeBetween(3599, 3601);
});

it('requires a signature for the named profile exactly like the alias form', function (): void {
    partnerRing();
    config()->set('sentinel.signatures.profiles.partners', config('sentinel.signatures.profiles.default'));
    Route::post('/events', static fn (): string => 'ok')->middleware(VerifyHttpSignature::profile('partners'));

    expect(app(Kernel::class)->handle(received(signedPartnerRequest()))->getStatusCode())->toBe(200)
        ->and($this->postJson('/events')->status())->toBe(401);
});

it('refuses invalid parameters when the helper is called', function (Closure $helper, string $message): void {
    expect($helper)->toThrow(SealingMisconfiguredException::class, $message);
})->with([
    'malformed route parameter' => [static fn (): string => VerifySeals::using('invoice@financial', 'bad param!'), '[(invalid)] is not a valid option of the sentinel.verified middleware'],
    'malformed seal name' => [static fn (): string => VerifySeals::using('invoice@Financial'), '[(invalid)] is not a valid option of the sentinel.verified'],
    'short ttl' => [static fn (): string => EnsureIdempotency::required(ttl: 59), '[59] is not a valid option of the sentinel.idempotent middleware'],
    'long ttl' => [static fn (): string => EnsureIdempotency::optional(ttl: 2592001), '[2592001] is not a valid option'],
    'unknown profile' => [static fn (): string => VerifyHttpSignature::profile('partners'), '[partners] is not a valid option of the sentinel.signed middleware'],
    'malformed profile' => [static fn (): string => VerifyHttpSignature::profile('Bad Profile'), 'is not a valid option of the sentinel.signed middleware'],
]);
