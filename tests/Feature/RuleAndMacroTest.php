<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\CollectionMacros;
use RoundlyConsulting\Sentinel\Rules\IntactSeal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

/**
 * §10 item 24: the `IntactSeal` rule and the `verifySeals()` collection macro.
 */
it('validates that a referenced model exists and is intact', function (): void {
    $intact = invoice(['number' => 'INV-1']);
    $tampered = invoice(['number' => 'INV-2']);
    DB::table('invoices')->where('id', $tampered->id)->update(['amount' => '0.00']);
    $rule = new IntactSeal(Invoice::class, seal: 'financial');

    $validate = static fn (mixed $value, IntactSeal $rule): array => Validator::make(['invoice' => $value], ['invoice' => [$rule]])->errors()->get('invoice');

    expect($validate($intact->id, $rule))->toBe([])
        ->and($validate($tampered->id, $rule))->toBe(['The selected invoice failed an integrity check.'])
        ->and($validate(999999, $rule))->toBe(['The selected invoice is invalid.'])
        ->and($validate(['array'], $rule))->toBe(['The selected invoice is invalid.'])
        ->and($validate('INV-1', new IntactSeal(Invoice::class, column: 'number')))->toBe([])
        ->and($validate('INV-2', new IntactSeal(Invoice::class, column: 'number')))->toHaveCount(1)
        ->and(fn () => new IntactSeal(Invoice::class, column: 'number; drop'))->toThrow(SealingMisconfiguredException::class);
});

it('translates the rule message', function (): void {
    $tampered = invoice();
    DB::table('invoices')->where('id', $tampered->id)->update(['amount' => '0.00']);
    app()->setLocale('sk');

    $errors = Validator::make(['faktura' => $tampered->id], ['faktura' => [new IntactSeal(Invoice::class)]])->errors()->get('faktura');

    expect($errors)->toBe(['Vybraný faktura neprešiel kontrolou integrity.']);
});

it('verifies a collection and reuses its eager-loaded seals', function (): void {
    invoice();
    $tampered = invoice();
    invoice();
    DB::table('invoices')->where('id', $tampered->id)->update(['amount' => '0.00']);

    $invoices = Invoice::query()->withSeals()->get();

    $count = static function (Closure $run): int {
        DB::flushQueryLog();
        DB::enableQueryLog();
        $run();
        $queries = count(DB::getQueryLog());
        DB::disableQueryLog();

        return $queries;
    };

    $report = $invoices->verifySeals('identity');
    $full = $invoices->verifySeals();

    // identity has neither a scope nor computed fields: the loaded values and seal rows are
    // reused, leaving only the one ledger query per model — or none without the ledger check.
    expect($count(static fn () => $invoices->verifySeals('identity')))->toBe(3);

    config()->set('sentinel.verification.check_ledger', false);

    expect($count(static fn () => $invoices->verifySeals('identity')))->toBe(0)
        ->and($report->allIntact())->toBeTrue()
        ->and($report->results)->toHaveCount(3)
        ->and($full->count(VerificationStatus::Tampered))->toBe(1)
        ->and($full->results[0]->context)->toBe(VerificationContext::Collection);
});

it('looks a seal up when a constrained eager load left it out', function (): void {
    invoice();

    $invoices = Invoice::query()->with(['sentinelSeals' => static fn ($seals) => $seals->where('seal', 'identity')])->get();

    expect($invoices->verifySeals('financial')->allIntact())->toBeTrue();
});

it('registers the macro once', function (): void {
    CollectionMacros::register();
    CollectionMacros::register();

    expect(Collection::hasMacro('verifySeals'))->toBeTrue();
});

it('drives the rule and the macro through the fake', function (): void {
    $invoice = invoice();
    $fake = Sentinel::fake();
    $fake->fakeStatus($invoice, VerificationStatus::Tampered, 'financial');

    expect(Validator::make(['i' => $invoice->id], ['i' => [new IntactSeal(Invoice::class)]])->fails())->toBeTrue()
        ->and(Invoice::query()->get()->verifySeals()->count(VerificationStatus::Tampered))->toBe(1);

    $fake->assertVerified($invoice, 'financial');
});
