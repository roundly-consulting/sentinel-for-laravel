<?php

declare(strict_types=1);

use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Exceptions\SealVerificationFailedHttpException;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

beforeEach(function (): void {
    config()->set('app.debug', false);

    Route::get('/all/{invoice}', static fn (Invoice $invoice): string => 'ok:'.$invoice->id)
        ->middleware([SubstituteBindings::class, 'sentinel.verified']);
    Route::get('/financial/{invoice}', static fn (Invoice $invoice): string => 'ok')
        ->middleware([SubstituteBindings::class, 'sentinel.verified:invoice@financial']);
    Route::get('/unbound/{invoice}', static fn (Invoice $invoice): string => 'ok')
        ->middleware([SubstituteBindings::class, 'sentinel.verified:other']);
    Route::get('/raw/{invoice}', static fn (string $invoice): string => 'ok')
        ->middleware(['sentinel.verified:invoice']);
    Route::get('/early/{invoice}', static fn (Invoice $invoice): string => 'ok')
        ->middleware(['sentinel.verified', SubstituteBindings::class]);
    Route::middleware('web')->get('/web/{invoice}', static fn (Invoice $invoice): string => 'ok')
        ->middleware('sentinel.verified');
    Route::get('/plain/{id}', static fn (string $id): string => 'plain:'.$id)
        ->middleware('sentinel.verified');
});

/**
 * §10 item 23: `sentinel.verified`.
 */
it('lets intact models through and refuses tampered ones with a generic 409', function (): void {
    Event::fake([TamperDetected::class]);
    $invoice = invoice();

    $this->get("/all/{$invoice->id}")->assertOk()->assertSee("ok:{$invoice->id}");
    $this->get('/plain/7')->assertOk();

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);
    $response = $this->getJson("/all/{$invoice->id}");

    $response->assertStatus(409)->assertJson(['message' => 'The requested resource failed an integrity check.']);

    expect($response->getContent())->not->toContain('tampered')->not->toContain('mac')->not->toContain('amount');

    Event::assertDispatched(TamperDetected::class, static fn (TamperDetected $event): bool => $event->context === VerificationContext::Middleware);
});

it('verifies only the named parameters and seals', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['number' => 'changed']);

    $this->get("/financial/{$invoice->id}")->assertOk();
    $this->get("/all/{$invoice->id}")->assertStatus(409);
});

it('fails closed on a misconfigured route', function (string $uri): void {
    $invoice = invoice();

    $this->withoutExceptionHandling();

    expect(fn () => $this->get(str_replace('{id}', (string) $invoice->id, $uri)))->toThrow(SealingMisconfiguredException::class);
})->with([
    'an unknown parameter' => ['/unbound/{id}'],
    'a parameter that is no model' => ['/raw/{id}'],
    'before route-model binding' => ['/early/{id}'],
]);

it('runs after route-model binding inside the web group', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

    $this->get("/web/{$invoice->id}")->assertStatus(409);
});

it('only reports when configured to', function (): void {
    Event::fake([TamperDetected::class]);
    config()->set('sentinel.middleware.verified_reaction', 'report');
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

    $this->get("/all/{$invoice->id}")->assertOk();

    Event::assertDispatched(TamperDetected::class);
});

it('answers with the configured status and keeps the finding for the logs', function (): void {
    config()->set('sentinel.middleware.verified_status', 423);
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

    $this->withoutExceptionHandling();

    try {
        $this->get("/all/{$invoice->id}");
        $this->fail('The request was not refused.');
    } catch (SealVerificationFailedHttpException $exception) {
        expect($exception->getStatusCode())->toBe(423)
            ->and($exception->getPrevious()?->getMessage())->toContain('tampered');
    }
});

it('is driven by the fake in tests', function (): void {
    $invoice = invoice();
    Sentinel::fake()->fakeStatus($invoice, VerificationStatus::Tampered, 'financial');

    $this->get("/all/{$invoice->id}")->assertStatus(409);
    $this->get("/financial/{$invoice->id}")->assertStatus(409);

    Sentinel::assertVerified($invoice, 'financial');
    Sentinel::assertVerified($invoice, 'identity');
});
