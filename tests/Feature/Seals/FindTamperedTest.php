<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

/**
 * I-16: an acknowledgement screen can load the tampered model a `Throw` retrieve seal guards.
 */
function guardedInvoiceClass(): string
{
    return definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount')->verifyOnRetrieve(Reaction::Throw));
}

it('loads a tampered model that a plain find refuses', function (): void {
    $class = guardedInvoiceClass();
    $model = $class::query()->create(['number' => 'T-1', 'amount' => '5.00']);
    DB::table('invoices')->where('id', $model->getKey())->update(['amount' => '0.00']);

    $found = Sentinel::model($class)->find($model->getKey());

    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class)
        ->and($found?->getKey())->toBe($model->getKey())
        ->and(Sentinel::model($class)->findOrFail((string) $model->getKey())->getKey())->toBe($model->getKey())
        ->and(Sentinel::model($class)->find(999))->toBeNull()
        ->and(fn () => Sentinel::model($class)->findOrFail(999))->toThrow(ModelNotFoundException::class, "No query results for model [{$class}] 999");

    // Verification stays on outside the call.
    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class);
});

it('binds a tampered model to an acknowledgement route, and 404s an unknown id', function (): void {
    $class = guardedInvoiceClass();
    $model = $class::query()->create(['number' => 'T-2', 'amount' => '5.00']);
    DB::table('invoices')->where('id', $model->getKey())->update(['amount' => '0.00']);

    Route::bind('tamperedInvoice', static fn (string $id) => Sentinel::model($class)->findOrFail($id));
    Route::post('/admin/invoices/{tamperedInvoice}/acknowledge', static fn ($tamperedInvoice): array => [
        'acknowledged' => Sentinel::acknowledge($tamperedInvoice, 'INC-12: reviewed')->acknowledged,
    ])->middleware(SubstituteBindings::class);

    expect($this->postJson("/admin/invoices/{$model->getKey()}/acknowledge")->json('acknowledged'))->toBeTrue()
        ->and($this->postJson('/admin/invoices/999/acknowledge')->status())->toBe(404)
        ->and($class::query()->find($model->getKey()))->not->toBeNull();
});

it('keeps global scopes', function (): void {
    $invoice = invoice();
    $invoice->delete();

    expect(Sentinel::model($invoice::class)->find($invoice->id))->toBeNull();
});

it('finds under the fake as in production', function (): void {
    $class = guardedInvoiceClass();
    $model = $class::query()->create(['number' => 'T-3']);
    $fake = Sentinel::fake();
    $fake->fakeStatus($model, VerificationStatus::Tampered);

    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class)
        ->and(Sentinel::model($class)->findOrFail($model->getKey())->getKey())->toBe($model->getKey());
});
