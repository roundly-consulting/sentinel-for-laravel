<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyKeyReusedException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Jobs\ChargeJob;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\InvoiceLine;

/**
 * Fake parity (plan §12.4, fleet theme 7): every scenario runs once against the real manager
 * and once under Sentinel::fake(), and both must agree — the same exception class, the same
 * statuses and results, the same in-memory model and the same rows. A test written against
 * the fake therefore proves what production does.
 *
 * The only thing that differs between the two runs is how a model gets tampered with: an
 * out-of-band UPDATE for the real manager, a scripted status for the fake.
 */
final class ParityRun
{
    public function __construct(public readonly bool $fake) {}

    /**
     * Change the invoice's sealed amount behind the application's back.
     */
    public function tamper(Invoice $invoice): void
    {
        $manager = app(SentinelManager::class);

        if ($this->fake && $manager instanceof SentinelFake) {
            $manager->fakeStatus($invoice, VerificationStatus::Tampered, 'financial', ['a:amount']);

            return;
        }

        DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);
    }

    /**
     * Change a computed field's source rows (the fake scripts the drift a real verification
     * proves with the attribute MAC).
     */
    public function drift(Invoice $invoice): void
    {
        $manager = app(SentinelManager::class);

        if ($this->fake && $manager instanceof SentinelFake) {
            $manager->fakeStatus($invoice, VerificationStatus::Tampered, 'financial', ['c:lines']);

            return;
        }

        DB::table('invoice_lines')->insert(['invoice_id' => $invoice->id, 'sku' => 'D-1', 'quantity' => 2]);
    }

    /**
     * Rewrite a ledger entry behind the application's back (the fake scripts the finding a
     * real verification reports for it).
     */
    public function rewriteLedger(Invoice $invoice): void
    {
        $manager = app(SentinelManager::class);

        if ($this->fake && $manager instanceof SentinelFake) {
            $manager->fakeLedgerFindings(new LedgerFinding(LedgerFindingKind::EntryInvalid, null, 1, Invoice::class, $invoice->id, 'financial', 'mac', 'testing'));

            return;
        }

        LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->toBase()->update(['reason' => 'rewritten']);
    }

    /**
     * What a test can observe of an invoice: the verdicts, the in-memory model, the row.
     *
     * @return array<string, mixed>
     */
    public function state(Invoice $invoice): array
    {
        return [
            'financial' => Sentinel::verify($invoice, 'financial')->status->value,
            'identity' => Sentinel::verify($invoice, 'identity')->status->value,
            'memory' => ['note' => $invoice->note, 'dirty' => array_keys($invoice->getDirty()), 'exists' => $invoice->exists],
            'row' => DB::table('invoices')->where('id', $invoice->id)->value('note'),
        ];
    }
}

/**
 * @param  Closure(ParityRun): mixed  $scenario
 * @return array<string, mixed>
 */
function observeParity(Closure $scenario, ParityRun $run): array
{
    try {
        return ['result' => $scenario($run)];
    } catch (Throwable $exception) {
        return ['exception' => $exception::class];
    }
}

it('behaves exactly like the real manager', function (Closure $scenario): void {
    $real = observeParity($scenario, new ParityRun(false));

    Sentinel::fake();
    $faked = observeParity($scenario, new ParityRun(true));

    expect($faked)->toBe($real)
        ->and(app(SentinelManager::class))->toBeInstanceOf(SentinelFake::class);
})->with([
    'unknown seal' => [static fn (): mixed => Sentinel::verify(invoice(), 'nope')],
    'not sealable' => [static fn (): mixed => Sentinel::verify(new InvoiceLine)],
    'unsaved model' => [static fn (): mixed => Sentinel::seal(new Invoice)],
    'acknowledge without a reason' => [static fn (): mixed => Sentinel::acknowledge(invoice(), '   ')],
    'acknowledge with an overlong reason' => [static fn (): mixed => Sentinel::acknowledge(invoice(), str_repeat('x', 1001))],
    'acknowledge an intact model' => [static function (ParityRun $run): array {
        $result = Sentinel::acknowledge($invoice = invoice(), 'nothing to see');

        return [$result->acknowledged, $result->before->status->value, $run->state($invoice)];
    }],
    'acknowledge a tampered model' => [static function (ParityRun $run): array {
        $run->tamper($invoice = invoice());
        $result = Sentinel::for($invoice)->because('INC-1: refund fixed by the DBA')->acknowledge();

        return [$result->acknowledged, $result->before->status->value, $result->before->changedAttributes, $run->state($invoice)];
    }],
    'acknowledgement refused by the policy' => [static function (ParityRun $run): array {
        config()->set('sentinel.acknowledgement.ability', 'acknowledge-tampering');
        Gate::define('acknowledge-tampering', static fn (): bool => false);
        $run->tamper($invoice = invoice());

        try {
            Sentinel::acknowledge($invoice, 'INC-2');
        } catch (Throwable $exception) {
            return [$exception::class, $run->state($invoice)];
        }

        return ['acknowledged'];
    }],
    'refuse a write on a tampered model' => [static function (ParityRun $run): array {
        $run->tamper($invoice = invoice());

        try {
            $invoice->update(['note' => 'after the tamper']);
        } catch (Throwable $exception) {
            return [$exception::class, $run->state($invoice)];
        }

        return ['written'];
    }],
    'reseal a write on a tampered model' => [static function (ParityRun $run): array {
        config()->set('sentinel.sealing.on_tampered_write', 'reseal');
        $run->tamper($invoice = invoice());

        return [$invoice->update(['note' => 'after the tamper']), $run->state($invoice)];
    }],
    'skip a write on a tampered model' => [static function (ParityRun $run): array {
        config()->set('sentinel.sealing.on_tampered_write', 'skip');
        $run->tamper($invoice = invoice());

        return [$invoice->update(['note' => 'after the tamper']), $run->state($invoice)];
    }],
    'refuse an explicit seal of a tampered model' => [static function (ParityRun $run): array {
        $run->tamper($invoice = invoice());

        try {
            Sentinel::seal($invoice);
        } catch (Throwable $exception) {
            return [$exception::class, $run->state($invoice)];
        }

        return ['sealed'];
    }],
    'computed drift: verified, re-sealed by a write and by seal() (dual-review O-1)' => [static function (ParityRun $run): array {
        $run->drift($first = invoice());
        $run->drift($second = invoice());
        $drift = Sentinel::verify($first, 'financial');

        return [
            $drift->status->value, $drift->reason, $drift->onlyComputedChanged(), $drift->changedComputed(),
            $first->update(['note' => 'routine']), $run->state($first),
            Sentinel::seal($second, 'financial')->event->value, $run->state($second),
        ];
    }],
    'a listener cancels the save' => [static function (ParityRun $run): array {
        $invoice = invoice();
        $cancel = true;
        Invoice::saving(static function () use (&$cancel): ?bool {
            return $cancel ? $cancel = false : null;
        });

        return [$invoice->update(['note' => 'cancelled']), $run->state($invoice)];
    }],
    'suspension disallowed' => [static function (): mixed {
        config()->set('sentinel.sealing.allow_suspension', false);

        return Sentinel::withoutSealing(static fn (): int => 1, 'import');
    }],
    'suspension allowed' => [static fn (): mixed => Sentinel::withoutSealing(static fn (): string => 'ran', 'import')],
    'idempotency: run, replay, 422 and 409' => [static function (): array {
        $runs = 0;
        $charge = static function () use (&$runs): array {
            return ['charge' => 'ch_'.++$runs];
        };
        $first = Sentinel::idempotency()->run('charge:42', 'billing', $charge, fingerprint: 'order 42');
        $second = Sentinel::idempotency()->run('charge:42', 'billing', $charge, fingerprint: 'order 42');
        $outcomes = [[$first->value, $first->replayed], [$second->value, $second->replayed], $runs];

        try {
            Sentinel::idempotency()->run('charge:42', 'billing', $charge, fingerprint: 'order 43');
        } catch (IdempotencyKeyReusedException $exception) {
            $outcomes[] = [$exception::class, $exception->getStatusCode()];
        }

        Sentinel::idempotency()->run('charge:43', 'billing', static function () use (&$outcomes): int {
            try {
                Sentinel::idempotency()->run('charge:43', 'billing', static fn (): int => 0);
            } catch (IdempotencyRequestInProgressException $exception) {
                $outcomes[] = [$exception::class, $exception->getStatusCode()];
            }

            return 1;
        });

        return [...$outcomes, Sentinel::idempotency()->forget('charge:42', 'billing'), Sentinel::idempotency()->forget('charge:42', 'billing')];
    }],
    'idempotent route: 5xx released, retried, replayed' => [static function (): array {
        $responses = [500, 201];
        Route::post('/parity/orders', static function () use (&$responses) {
            return response()->json(['ok' => true], array_shift($responses) ?? 200);
        })->middleware('sentinel.idempotent:required');
        $request = static fn () => test()->postJson('/parity/orders', ['sku' => 'A-1'], ['Idempotency-Key' => '"8e03978e-40d5-43e8-bc93-6894a57f9324"']);

        return array_map(static fn ($response): array => [$response->status(), $response->headers->get('Idempotent-Replayed')], [$request(), $request(), $request()]);
    }],
    'nonce consumed twice' => [static function (): array {
        $nonce = Sentinel::nonces()->issue('password-reset');

        return [
            Sentinel::nonces()->consume('password-reset', $nonce->value),
            Sentinel::nonces()->consume('password-reset', $nonce->value),
            Sentinel::nonces()->consume('another-purpose', Sentinel::nonces()->issue('password-reset')->value),
        ];
    }],
    'import a partner key, verify-only' => [static function (): array {
        $info = Sentinel::keys()->ring('http')->import('acme', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPublic(), label: 'Acme');

        return [$info->ring, $info->keyId, $info->algorithm->value, $info->status->value, $info->driver, $info->canSign, $info->label];
    }],
    'import a signing key' => [static function (): array {
        $info = Sentinel::keys()->ring('http')->import('own', Algorithm::HmacSha256, PARTNER_SECRET, signing: true);

        return [$info->status->value, $info->canSign];
    }],
    'import private material without signing' => [static fn (): mixed => Sentinel::keys()->ring('http')->import('own', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate())],
    'import into a config-only ring' => [static function (): mixed {
        partnerRing();

        return Sentinel::keys()->ring('http')->import('acme', Algorithm::HmacSha256, PARTNER_SECRET);
    }],
    'import a passphrase' => [static fn (): mixed => Sentinel::keys()->ring('http')->import('acme', Algorithm::HmacSha256, 'a passphrase')],
    'import an algorithm the ring refuses' => [static fn (): mixed => Sentinel::keys()->ring('http')->import('acme', Algorithm::HmacSha512, PARTNER_SECRET)],
    'job middleware: a duplicate, a failure, a self-release' => [static function (): array {
        ChargeJob::$runs = 0;
        ChargeJob::$behaviour = ['complete', 'throw', 'release'];
        ChargeJob::dispatch('parity-1');
        ChargeJob::dispatch('parity-1');

        try {
            ChargeJob::dispatch('parity-2');
        } catch (RuntimeException) {
            // The job threw: the key is free for the retry.
        }

        ChargeJob::dispatch('parity-2');
        ChargeJob::dispatch('parity-2');

        return [ChargeJob::$runs];
    }],
    'scoped scan with progress' => [static function (ParityRun $run): array {
        // Each run its own tenant: the real run's rows are still there when the fake runs.
        $tenant = $run->fake ? 17 : 7;
        invoice(['tenant_id' => $tenant]);
        invoice(['tenant_id' => $tenant]);
        $run->tamper(invoice(['tenant_id' => $tenant]));
        invoice(['tenant_id' => $tenant + 1]);
        $progress = [];

        $report = Sentinel::model(Invoice::class)->scan('financial', chunk: 2, where: static fn ($query) => $query->where('tenant_id', $tenant), progress: static function (int $processed) use (&$progress): void {
            $progress[] = $processed;
        });

        return [$report->scanned, array_map(static fn ($count): string => $count->status->value.':'.$count->count, $report->counts), $progress];
    }],
    'ledger verification of a rewritten entry' => [static function (ParityRun $run): array {
        $run->rewriteLedger(invoice());
        $report = Sentinel::ledger()->verify(entities: false);

        try {
            $report->throwIfViolated();
            $thrown = null;
        } catch (Throwable $exception) {
            $thrown = $exception::class;
        }

        return [$report->clean(), array_map(static fn (LedgerFinding $finding): string => $finding->kind->value, $report->violations()), $thrown];
    }],
    'client nonce remembered twice' => [static fn (): array => [
        app(SentinelManager::class)->rememberNonce('http:partner', 'n-1', Clock::now()->addMinutes(5)),
        app(SentinelManager::class)->rememberNonce('http:partner', 'n-1', Clock::now()->addMinutes(5)),
    ]],
]);

it('hands the fake to code that injected the manager, and records the model-trait path', function (): void {
    $consumer = new class(app(SentinelManager::class))
    {
        public function __construct(public readonly SentinelManager $sentinel) {}
    };
    $fake = Sentinel::fake();
    $invoice = Invoice::query()->create(['number' => 'P-1']);

    expect(app($consumer::class)->sentinel)->toBe($fake)
        ->and($fake->recorded('seal'))->toHaveCount(2);

    $fake->assertSealed($invoice, 'financial');
    $fake->assertSealed($invoice, 'identity');
});
