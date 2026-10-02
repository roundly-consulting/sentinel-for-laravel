<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIntegrityException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

/**
 * I-9: every mutating verb of the fake has an `assert<Verb>` and an `assertNothing<Verb>` /
 * `assertNot<Verb>`, each passing and failing — through the facade, a sub-accessor and, where
 * the verb has one, the model trait.
 */
function fails(Closure $assertion, string $message): void
{
    expect($assertion)->toThrow(ExpectationFailedException::class, $message);
}

it('asserts verifications that did not happen — through the facade and the trait', function (): void {
    $fake = Sentinel::fake();
    $invoice = Invoice::query()->create(['number' => 'A-1']);
    $other = Invoice::query()->create(['number' => 'A-2']);

    $fake->assertNotVerified($invoice);
    Sentinel::assertNotVerified($invoice, 'identity');

    $invoice->verifySeal('identity');

    $fake->assertNotVerified($invoice, 'financial');
    $fake->assertNotVerified($other);
    fails(fn () => $fake->assertNotVerified($invoice), 'not to be verified, but it was');
    fails(fn () => $fake->assertNotVerified($invoice, 'identity'), 'seal [identity] not to be verified');
});

it('asserts acknowledgements that did not happen — through the facade and the trait', function (): void {
    $fake = Sentinel::fake();
    $invoice = Invoice::query()->create(['number' => 'B-1']);
    $other = Invoice::query()->create(['number' => 'B-2']);

    // Acknowledging an intact model is not an acknowledgement.
    Sentinel::acknowledge($invoice, 'nothing to see');
    $fake->assertNotAcknowledged($invoice);

    $fake->fakeStatus($invoice, VerificationStatus::Tampered);
    $invoice->acknowledgeTampering('INC-9');

    $fake->assertNotAcknowledged($other);
    fails(fn () => $fake->assertNotAcknowledged($invoice), 'not to be acknowledged, but it was');
});

it('asserts that nothing was unsealed, and that sealing was not suspended', function (): void {
    $fake = Sentinel::fake();
    $invoice = Invoice::query()->create(['number' => 'C-1']);

    $fake->assertNothingUnsealed();
    $fake->assertSealingNotSuspended();

    Sentinel::for($invoice, 'identity')->because('archived')->unseal();
    Sentinel::withoutSealing(static fn (): null => null, 'import');

    fails(fn () => $fake->assertNothingUnsealed(), '1 seal removal(s) were recorded');
    fails(fn () => $fake->assertSealingNotSuspended(), 'suspended 1 time(s)');
});

it('asserts scans per model, through the handle', function (): void {
    $fake = Sentinel::fake();

    fails(fn () => $fake->assertScanned(), 'Expected a seal scan, but none ran.');

    Sentinel::model(Invoice::class)->scan();

    $fake->assertScanned();
    $fake->assertScanned(Invoice::class);
    fails(fn () => $fake->assertScanned(PlainRecord::class), 'Expected ['.PlainRecord::class.'] to be scanned');
});

it('asserts that nothing was re-sealed by any bulk verb', function (Closure $bulk): void {
    $fake = Sentinel::fake();
    Invoice::query()->create(['number' => 'D-1']);

    $fake->assertNothingResealed();

    $bulk();

    fails(fn () => $fake->assertNothingResealed(), '1 bulk re-seal(s) were recorded');
})->with([
    'reseal' => [static fn () => Sentinel::model(Invoice::class)->reseal()],
    'resealWhere' => [static fn () => Sentinel::model(Invoice::class)->resealWhere(static fn ($query) => $query, 'reviewed')],
    'updateAndReseal' => [static fn () => Sentinel::model(Invoice::class)->updateAndReseal(static fn ($query) => $query, ['note' => 'x'], 'bulk')],
    'sealMissing' => [static fn () => Sentinel::model(Invoice::class)->sealMissing('baseline')],
]);

it('asserts retired keys, through the ring handle', function (): void {
    $fake = Sentinel::fake();

    fails(fn () => $fake->assertKeyRetired('k-1'), 'Expected key [k-1] to be retired');

    Sentinel::keys()->ring()->retire('k-1');

    $fake->assertKeyRetired('k-1');
    fails(fn () => $fake->assertKeyRetired('k-2'), 'Expected key [k-2] to be retired');
    fails(fn () => $fake->assertNoKeyChanges(), '1 were recorded');
});

it('asserts ledger verification and scripts its findings', function (): void {
    $fake = Sentinel::fake();

    fails(fn () => $fake->assertLedgerVerified(), 'Expected the ledger to be verified');

    expect(Sentinel::ledger()->verify()->clean())->toBeTrue();
    $fake->assertLedgerVerified();

    $violation = new LedgerFinding(LedgerFindingKind::ChainBroken, 3, 17, Invoice::class, 1, 'financial', 'previous digest mismatch', 'default');
    $backlog = new LedgerFinding(LedgerFindingKind::Backlog, null, null, null, null, null, '12 entries pending', 'default');
    $fake->fakeLedgerFindings($backlog);

    $report = Sentinel::verifyLedger();

    expect($report->clean())->toBeTrue()
        ->and($report->findings)->toBe([$backlog]);

    $report->throwIfViolated();

    expect($fake->fakeLedgerFindings($backlog, $violation))->toBe($fake);

    $sticky = Sentinel::ledger()->verify();

    expect($sticky->violations())->toBe([$violation])
        ->and(Sentinel::verifyLedger()->violations())->toBe([$violation])
        ->and(fn () => $sticky->throwIfViolated())->toThrow(LedgerIntegrityException::class);

    $fake->fakeLedgerFindings();

    expect(Sentinel::verifyLedger()->findings)->toBe([]);
});

it('fails sentinel:verify --ledger on scripted violations under the fake', function (): void {
    Invoice::query()->create(['number' => 'E-1']);
    $fake = Sentinel::fake();
    $fake->fakeLedgerFindings(new LedgerFinding(LedgerFindingKind::CheckpointMismatch, 1, null, null, null, null, 'root mismatch', 'default'));

    expect(Artisan::call('sentinel:verify', ['model' => [Invoice::class], '--ledger' => true]))->toBe(1)
        ->and(Artisan::output())->toContain('checkpoint_mismatch');

    $fake->fakeLedgerFindings();

    expect(Artisan::call('sentinel:verify', ['model' => [Invoice::class], '--ledger' => true]))->toBe(0);

    $fake->assertScanned(Invoice::class);
    $fake->assertLedgerVerified();
});

it('asserts idempotent runs that did not happen, and forgotten keys', function (): void {
    $fake = Sentinel::fake();

    $fake->assertNoIdempotentRuns();
    fails(fn () => $fake->assertIdempotencyKeyForgotten('charge:1'), 'Expected the idempotency key to be forgotten');

    Sentinel::idempotency()->run('charge:1', 'billing', static fn (): int => 1);
    Sentinel::idempotency()->forget('charge:1', 'billing');

    $fake->assertIdempotencyKeyForgotten('charge:1');
    fails(fn () => $fake->assertIdempotencyKeyForgotten('charge:2'), 'Expected the idempotency key to be forgotten');
    fails(fn () => $fake->assertNoIdempotentRuns(), 'but 1 were recorded');
});

it('asserts nonces not issued or not consumed, and single-use URLs', function (): void {
    Route::get('/exports/{export}', static fn (): string => 'ok')->name('exports.download')->middleware('sentinel.single-use');
    $fake = Sentinel::fake();

    $fake->assertNoNoncesIssued();
    $fake->assertNonceNotConsumed('password-reset');
    fails(fn () => $fake->assertSingleUseUrlIssued(), 'Expected a single-use URL to be issued');

    $nonce = Sentinel::nonces()->issue('password-reset');
    Sentinel::nonces()->consume('password-reset', 'not-the-nonce-at-all-0000000000000000000000');

    $fake->assertNonceNotConsumed('password-reset');
    fails(fn () => $fake->assertNoNoncesIssued(), 'but 1 were');

    Sentinel::nonces()->consume('password-reset', $nonce->value);
    Sentinel::nonces()->signedRoute('exports.download', ['export' => 7]);

    $fake->assertSingleUseUrlIssued();
    $fake->assertSingleUseUrlIssued('exports.download');
    fails(fn () => $fake->assertNonceNotConsumed('password-reset'), 'but one was');
    fails(fn () => $fake->assertSingleUseUrlIssued('other'), 'Expected a single-use URL for route [other]');
});

it('asserts pruning', function (): void {
    $fake = Sentinel::fake();

    fails(fn () => $fake->assertPruned(), 'Expected expired idempotency keys and nonces to be pruned');

    Sentinel::prune();

    $fake->assertPruned();
});

it('asserts that nothing was signed, and verified signatures per profile', function (): void {
    config()->set('sentinel.signatures.profiles.partners', config('sentinel.signatures.profiles.default'));
    $fake = Sentinel::fake();

    $fake->assertNothingSigned();
    fails(fn () => $fake->assertSignatureVerified(), 'Expected a signature to be verified, but none was.');

    $fake->rejectSignatures(SignatureRejection::InvalidSignature);

    expect(fn () => Sentinel::signatures()->verify(received(new PsrRequest('POST', 'https://api.example.com/x'))))->toThrow(HttpSignatureException::class);
    fails(fn () => $fake->assertSignatureVerified(), 'Expected a signature to be verified, but none was.');

    $fake->fakeVerifiedSignature();
    Sentinel::signatures()->verify(received(new PsrRequest('POST', 'https://api.example.com/x')), 'partners');
    Sentinel::signatures()->verifyResponse(new PsrResponse(200));
    Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example.com/'), 'outbound');

    $fake->assertSignatureVerified();
    $fake->assertSignatureVerified('partners');
    $fake->assertSignatureVerified('default');
    fails(fn () => $fake->assertSignatureVerified('other'), 'against profile [other]');
    fails(fn () => $fake->assertNothingSigned(), 'but 1 request(s) were');

    expect(DB::table('sentinel_nonces')->count())->toBe(0);
});
