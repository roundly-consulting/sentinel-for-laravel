<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\Actions\Seals\VerifyModelAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyRequest;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\SealingSuspensionNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\SealHandle;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\SentinelServiceProvider;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\InvoiceLine;

/**
 * The public API contract — Actions → Manager → Facade (+ fake) — pinned.
 */
it('pins the facade contract', function (): void {
    expect(Sentinel::class)
        ->toDocumentItsRoot()
        ->toBeFakeable()
        ->toReachEveryAction(__DIR__.'/../../src/Actions');
});

/*
 * A flat call (`Sentinel::verifyMac(…)`) passes Laravel's `Facade::__callStatic`, whose frame
 * holds the raw arguments: the facade must hide there exactly what the manager marks
 * `#[SensitiveParameter]` — `rememberNonce()`'s `$nonce` and `verifyMac()`'s `$mac`.
 */
it('hides secret arguments in the facade frame of a flat call', function (): void {
    expect(Sentinel::class)->toRedactSensitiveArguments(methods: 2);
});

it('declares no global alias, so a host using cartalyst/sentinel keeps its own Sentinel', function (): void {
    // cartalyst/sentinel registers the global alias `Sentinel`; a package-discovered alias of
    // ours would silently replace it. laravel/sentinel ships Laravel\Sentinel\Sentinel (no
    // alias). Hosts import RoundlyConsulting\Sentinel\Facades\Sentinel explicitly.
    /** @var array{extra: array{laravel: array<string, mixed>}} $composer */
    $composer = json_decode((string) file_get_contents(__DIR__.'/../../composer.json'), true, flags: JSON_THROW_ON_ERROR);

    expect($composer['extra']['laravel'])->not->toHaveKey('aliases')
        ->and($composer['extra']['laravel']['providers'] ?? null)->toBe([SentinelServiceProvider::class])
        ->and(class_exists('Sentinel'))->toBeFalse();
});

it('runs one API through the facade, an injected manager and the raw action', function (): void {
    $invoice = invoice();

    $facade = Sentinel::verify($invoice);
    $injected = app(SentinelManager::class)->verify($invoice);
    $action = app(VerifyModelAction::class)->execute(new VerifyRequest($invoice, 'financial'));

    expect([$facade->status, $injected->status, $action->status])->toBe(array_fill(0, 3, VerificationStatus::Intact))
        ->and(app(SentinelManager::class))->toBe(app(SentinelManager::class))
        ->and(Sentinel::for($invoice))->toBeInstanceOf(SealHandle::class)
        ->and(Sentinel::for($invoice)->verify()->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::for($invoice)->isIntact())->toBeTrue()
        ->and(Sentinel::for($invoice)->verifyOrFail()->isIntact())->toBeTrue()
        ->and($invoice->verifySeal('identity')->status)->toBe(VerificationStatus::Intact)
        ->and($invoice->verifySealOrFail()->isIntact())->toBeTrue()
        ->and(Sentinel::verifyAll($invoice)->results)->toHaveCount(2)
        ->and(Sentinel::verifyMany([$invoice, invoice()])->results)->toHaveCount(4)
        ->and(Sentinel::verifyMany([$invoice], 'identity')->counts()[0]->count)->toBe(1)
        ->and(Sentinel::isIntact($invoice))->toBeTrue();
});

it('summarises many verdicts and throws on failures', function (): void {
    $intact = invoice();
    $first = invoice();
    $second = invoice();
    DB::table('invoices')->whereIn('id', [$first->id, $second->id])->update(['amount' => '0.00']);

    $report = Sentinel::verifyMany([$intact, $first, $second], 'financial');

    expect($report->allIntact())->toBeFalse()
        ->and($report->failures())->toHaveCount(2)
        ->and($report->count(VerificationStatus::Tampered))->toBe(2)
        ->and(array_map(static fn ($count): string => $count->status->value.':'.$count->count, $report->counts()))->toBe(['intact:1', 'tampered:2'])
        ->and(fn () => $report->throwIfTampered())->toThrow(TamperedModelException::class, '2 sealed model(s)')
        ->and(fn () => Sentinel::verifyMany([$first], 'financial')->throwIfTampered())->toThrow(TamperedModelException::class, 'tampered: mac');

    Sentinel::verifyMany([$intact])->throwIfTampered();
});

it('resolves actions through the container so a host override applies', function (): void {
    app()->bind(VerifyModelAction::class, static fn (): never => throw new RuntimeException('overridden'));

    Sentinel::verify(invoice());
})->throws(RuntimeException::class, 'overridden');

it('records model-trait writes, facade and injected calls under the fake — touching nothing', function (): void {
    $fake = Sentinel::fake();

    $invoice = Invoice::query()->create(['number' => 'F-1']);
    $invoice->update(['amount' => '9.00']);
    $invoice->update(['note' => 'not sealed: no column of the identity seal changed']);
    Sentinel::verify($invoice);
    app(SentinelManager::class)->verify($invoice, 'identity');
    $invoice->isIntact();

    expect(app(SentinelManager::class))->toBeInstanceOf(SentinelFake::class)
        ->and(Seal::query()->count())->toBe(0)
        // create: financial + identity; each update re-seals financial (computed lines) only.
        ->and($fake->recorded('seal'))->toHaveCount(4);

    $fake->assertSealed($invoice);
    $fake->assertSealed($invoice, 'identity');
    $fake->assertSealed($invoice, 'financial', static fn (SealResult $result): bool => $result->version === 3);
    Sentinel::assertVerified($invoice);
    Sentinel::assertVerified($invoice, 'identity');
});

it('scripts verification statuses and applies the real tampered-write policy', function (): void {
    $fake = Sentinel::fake();
    $invoice = Invoice::query()->create(['number' => 'F-2']);

    $fake->fakeStatus($invoice, VerificationStatus::Tampered, 'financial', ['a:amount']);

    expect(Sentinel::verify($invoice)->changedAttributes)->toBe(['a:amount'])
        ->and(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Intact)
        ->and(fn () => $invoice->update(['amount' => '1.00']))->toThrow(TamperedModelException::class)
        ->and(fn () => Sentinel::seal($invoice))->toThrow(TamperedModelException::class);

    $fake->fakeStatusOnce($invoice, VerificationStatus::Missing);

    expect(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Missing)
        ->and(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Intact);

    $result = Sentinel::for($invoice)->because('fixed')->acknowledge();

    expect($result->acknowledged)->toBeTrue()
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);

    $fake->assertAcknowledged($invoice);
    $fake->assertAcknowledged($invoice, 'fixed');
});

it('passes and fails every sealing assertion', function (): void {
    $fake = Sentinel::fake();
    $invoice = Invoice::query()->create(['number' => 'F-3']);
    DB::table('invoices')->insert(['id' => 999, 'number' => 'other']);
    $other = Invoice::query()->findOrFail(999);

    $fake->assertNothingVerified();
    $fake->assertNothingAcknowledged();

    config()->set('sentinel.sealing.allow_suspension', true);
    Sentinel::withoutSealing(fn () => null, 'import');
    Sentinel::unseal($invoice, 'archive', seal: 'identity');
    $fake->assertSealingSuspended();
    $fake->assertSealingSuspended('import');
    $fake->assertUnsealed($invoice, 'identity');

    expect(fn () => $fake->assertNothingSealed())->toThrow(ExpectationFailedException::class, 'seal(s) were recorded')
        ->and(fn () => $fake->assertNotSealed($invoice))->toThrow(ExpectationFailedException::class, 'not to be sealed')
        ->and(fn () => $fake->assertSealed($invoice, 'financial', static fn (): bool => false))->toThrow(ExpectationFailedException::class, 'matching result')
        ->and(fn () => $fake->assertVerified($invoice))->toThrow(ExpectationFailedException::class, 'to be verified')
        ->and(fn () => $fake->assertAcknowledged($invoice))->toThrow(ExpectationFailedException::class, 'to be acknowledged')
        ->and(fn () => $fake->assertUnsealed($invoice, 'financial'))->toThrow(ExpectationFailedException::class, 'to be unsealed')
        ->and(fn () => $fake->assertSealingSuspended('other'))->toThrow(ExpectationFailedException::class, '[other]');

    $fake->assertNotSealed($other);

    Sentinel::verify($invoice);
    $fake->fakeStatus($invoice, VerificationStatus::Tampered);
    Sentinel::acknowledge($invoice, 'ok');

    expect(fn () => $fake->assertNothingVerified())->toThrow(ExpectationFailedException::class, 'verification(s) were recorded')
        ->and(fn () => $fake->assertNothingAcknowledged())->toThrow(ExpectationFailedException::class, 'acknowledgement(s) were recorded');
});

it('fails assertSealingSuspended and assertNothingSealed passes on an untouched fake', function (): void {
    $fake = Sentinel::fake();
    $fake->assertNothingSealed();

    $fake->assertSealingSuspended();
})->throws(ExpectationFailedException::class, 'Expected sealing to be suspended');

it('keeps production validation in the fake (fake parity, §12.4)', function (): void {
    $fake = Sentinel::fake();
    $invoice = Invoice::query()->create(['number' => 'F-4']);

    expect(fn () => Sentinel::verify($invoice, 'nope'))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::verify(new InvoiceLine))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::acknowledge($invoice, ' '))->toThrow(AcknowledgementDeniedException::class)
        ->and(fn () => Sentinel::unseal($invoice, ''))->toThrow(AcknowledgementDeniedException::class)
        ->and(fn () => Sentinel::seal(new Invoice))->toThrow(SealingFailedException::class)
        ->and(Sentinel::acknowledge($invoice, 'intact')->acknowledged)->toBeFalse()
        ->and(Sentinel::ledgerHistory($invoice))->toBe([])
        ->and(Sentinel::currentSeal($invoice))->toBeNull()
        ->and(Sentinel::verifyMany([$invoice])->results)->toHaveCount(2)
        ->and(Sentinel::seal($invoice)->keyId)->toBe('fake');

    config()->set('sentinel.sealing.allow_suspension', false);

    expect(fn () => Sentinel::withoutSealing(fn () => null, 'x'))->toThrow(SealingSuspensionNotAllowedException::class);

    config()->set('sentinel.sealing.on_tampered_write', 'skip');
    $fake->fakeStatus($invoice, VerificationStatus::Tampered);
    $invoice->update(['amount' => '2.00']);

    config()->set('sentinel.sealing.on_tampered_write', 'reseal');
    $invoice->update(['amount' => '3.00']);

    config()->set('sentinel.sealing.auto', false);
    $invoice->update(['amount' => '4.00']);
    $invoice->delete();

    // create (2) + explicit seal (1) + skip (0) + reseal (2) + auto off (0); deletes record none.
    expect(count($fake->recorded('seal')))->toBe(5);
});

it('settles a faked status once the fake re-seals, and lets a new status for every seal replace it', function (): void {
    $fake = Sentinel::fake();
    config()->set('sentinel.sealing.on_tampered_write', 'reseal');
    $invoice = Invoice::query()->create(['number' => 'F-5']);
    $fake->fakeStatus($invoice, VerificationStatus::Tampered);

    $invoice->update(['note' => 're-sealed under the reseal policy']);

    expect(Sentinel::verify($invoice, 'financial')->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Intact);

    $fake->fakeStatus($invoice, VerificationStatus::Stale);
    $fake->fakeStatus($invoice, VerificationStatus::Missing, 'identity');

    expect(Sentinel::verify($invoice, 'financial')->status)->toBe(VerificationStatus::Stale)
        ->and(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Missing);

    $fake->fakeStatus($invoice, VerificationStatus::Tampered, 'financial');
    Sentinel::for($invoice, 'financial')->because('INC-5')->acknowledge();

    // Acknowledging one seal leaves the other seal's scripted status alone.
    expect(Sentinel::verify($invoice, 'financial')->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Missing);
});
