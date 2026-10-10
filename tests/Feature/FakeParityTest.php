<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyKeyReusedException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyRequestInProgressException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Jobs\ChargeJob;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\InvoiceLine;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;
use RoundlyConsulting\Sentinel\Tests\TestCase;

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
     * Delete the invoice's seal row behind the application's back.
     */
    public function deleteSeal(Invoice $invoice): void
    {
        $manager = app(SentinelManager::class);

        if ($this->fake && $manager instanceof SentinelFake) {
            $manager->fakeStatus($invoice, VerificationStatus::Missing, 'financial');

            return;
        }

        DB::table('sentinel_seals')->where('sealable_id', $invoice->id)->where('seal', 'financial')->delete();
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
    'seal() after a seal row was deleted or deliberately removed (dual-review O-18)' => [static function (ParityRun $run): array {
        $run->deleteSeal($deleted = invoice());
        $outcomes = [Sentinel::verify($deleted, 'financial')->reason];

        try {
            Sentinel::seal($deleted, 'financial');
        } catch (Throwable $exception) {
            $outcomes[] = $exception::class;
        }

        Sentinel::unseal($unsealed = invoice(), 'INC-6', seal: 'financial');
        Sentinel::unseal($unsealed, 'INC-6', seal: 'identity');
        $outcomes[] = Sentinel::verify($unsealed, 'financial')->reason;
        $outcomes[] = Sentinel::verify($unsealed, 'identity')->status->value;

        try {
            Sentinel::seal($unsealed, 'financial');
        } catch (Throwable $exception) {
            $outcomes[] = $exception::class;
        }

        return [...$outcomes, Sentinel::seal($unsealed, 'identity')->event->value, Sentinel::acknowledge($unsealed, 'INC-6 re-adopted', seal: 'financial')->acknowledged, $run->state($unsealed)];
    }],
    'unseal refused by the policy, and the actor it records (dual-review O-6)' => [static function (ParityRun $run): array {
        config()->set('sentinel.acknowledgement.ability', 'acknowledge-tampering');
        Gate::define('acknowledge-tampering', static fn (User $user): bool => $user->name === 'Admin');
        $invoice = invoice();
        $outcomes = [];

        try {
            Sentinel::unseal($invoice, 'cleanup', User::query()->create(['name' => 'Clerk']));
        } catch (Throwable $exception) {
            $outcomes[] = $exception::class;
        }

        app()->instance(Runtime::class, new Runtime(app(), console: false));

        try {
            Sentinel::unseal($invoice, 'cleanup');
        } catch (Throwable $exception) {
            $outcomes[] = $exception::class;
        }

        return [...$outcomes, Sentinel::unseal($invoice, 'INC-5', User::query()->create(['name' => 'Admin']), 'identity')];
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
    'listeners that save the model again inside its write (dual-review O-7)' => [static function (ParityRun $run): array {
        Invoice::created(static function (Invoice $invoice): void {
            $invoice->forceFill(['number' => 'INV-'.$invoice->getKey()])->saveQuietly();
        });
        Invoice::updated(static function (Invoice $invoice): void {
            if ($invoice->wasChanged('note')) {
                Invoice::query()->findOrFail($invoice->getKey())->forceFill(['number' => 'N-'.$invoice->getKey()])->save();
            }
        });
        $invoice = invoice();
        $invoice->update(['note' => 'changed']);

        return [$run->state($invoice), DB::table('invoices')->where('id', $invoice->id)->value('number') === 'N-'.$invoice->id];
    }],
    'a dry-run prune counts expired keys and nonces (dual-review O-29)' => [static function (): array {
        Sentinel::nonces()->issue('password-reset', ttl: 60);
        Sentinel::idempotency()->run('k-1', 'jobs', static fn (): int => 1, ttl: 60);
        Sentinel::idempotency()->run('k-2', 'jobs', static fn (): int => 2, ttl: 3600);
        test()->travel(120)->seconds();
        $dry = Sentinel::prune(new PruneOptions(dryRun: true));
        $real = Sentinel::prune(new PruneOptions);
        test()->travelBack();

        return [$dry->idempotencyKeys, $dry->nonces, $real->idempotencyKeys, $real->nonces];
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
    'suspension allowed' => [static function (): mixed {
        config()->set('sentinel.sealing.allow_suspension', true);

        return Sentinel::withoutSealing(static fn (): string => 'ran', 'import');
    }],
    'suspension not set' => [static fn (): mixed => Sentinel::withoutSealing(static fn (): int => 1, 'import')],
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
    // Each run its own kid: the real run's key is still stored when the fake runs, and the fake
    // refuses a kid the real store holds, as production does (chat review C-11).
    'import a partner key, verify-only' => [static function (ParityRun $run): array {
        $info = Sentinel::keys()->ring('http')->import($run->fake ? 'acme-fake' : 'acme-real', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPublic(), label: 'Acme');

        return [$info->ring, str_starts_with($info->keyId, 'acme-'), $info->algorithm->value, $info->status->value, $info->driver, $info->canSign, $info->label];
    }],
    'import a signing key' => [static function (ParityRun $run): array {
        $info = Sentinel::keys()->ring('http')->import($run->fake ? 'own-fake' : 'own-real', Algorithm::HmacSha256, PARTNER_SECRET, signing: true);

        return [$info->status->value, $info->canSign];
    }],
    'import a kid that is taken (chat review C-11)' => [static function (ParityRun $run): mixed {
        $kid = $run->fake ? 'imported-twice-fake' : 'imported-twice-real';
        Sentinel::keys()->ring('http')->import($kid, Algorithm::HmacSha256, PARTNER_SECRET);

        return Sentinel::keys()->ring('http')->import($kid, Algorithm::HmacSha256, PARTNER_SECRET);
    }],
    'import private material without signing' => [static fn (): mixed => Sentinel::keys()->ring('http')->import('own', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate())],
    'generate into a config-only ring (dual-review O-34)' => [static fn (): mixed => Sentinel::keys()->ring('default')->generate(Algorithm::HmacSha256)],
    'generate with an overlong label (dual-review O-34)' => [static fn (): mixed => Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, label: str_repeat('x', 300))],
    'generate a kid that is taken (dual-review O-34)' => [static function (ParityRun $run): mixed {
        $kid = $run->fake ? 'twice-fake' : 'twice-real';
        Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: $kid);

        return Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: $kid);
    }],
    'generate for the environment: lines and the public half (dual-review O-34)' => [static function (ParityRun $run): array {
        $generated = Sentinel::keys()->ring()->generate(Algorithm::Ed25519, keyId: 'env-key', destination: KeyDestination::Config);
        $stored = Sentinel::keys()->ring('http')->generate(Algorithm::Ed25519, keyId: $run->fake ? 'db-key-fake' : 'db-key-real');

        return [
            str_contains((string) $generated->envSnippet, 'SENTINEL_KEY_ID="env-key"'), str_starts_with((string) $generated->publicKey, 'base64:'),
            $generated->info->driver, $stored->envSnippet, str_starts_with((string) $stored->publicKey, 'base64:'), $stored->info->driver,
        ];
    }],
    'revoke or retire an unknown or a config key (dual-review O-34)' => [static function (ParityRun $run): array {
        $outcomes = [];

        foreach ([
            static fn (): mixed => Sentinel::revokeKey(new RevokeKeyRequest('http', 'nope', 'gone')),
            static fn (): mixed => Sentinel::revokeKey(new RevokeKeyRequest('default', 'test-default', 'gone')),
            static fn (): mixed => Sentinel::keys()->ring('http')->retire('nope'),
            static fn (): mixed => Sentinel::keys()->ring('default')->retire('test-default'),
        ] as $call) {
            try {
                $call();
                $outcomes[] = 'ok';
            } catch (Throwable $exception) {
                $outcomes[] = $exception::class;
            }
        }

        $kid = Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: $run->fake ? 'revocable-fake' : 'revocable-real')->info->keyId;

        return [...$outcomes, Sentinel::keys()->ring('http')->revoke($kid, 'leaked')->status->value, Sentinel::keys()->ring('http')->retire($kid)->status->value];
    }],
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

it('refuses to import a kid the real key store already holds under the fake (chat review C-11)', function (): void {
    Sentinel::keys()->ring('http')->import('acme-1', Algorithm::HmacSha256, PARTNER_SECRET);
    Sentinel::fake();

    expect(fn () => Sentinel::keys()->ring('http')->import('acme-1', Algorithm::HmacSha256, PARTNER_SECRET))
        ->toThrow(KeyDriverException::class, 'already has a key [acme-1]');
});

it('filters a re-seal like production under the fake (chat review C-12)', function (): void {
    invoice();
    invoice();
    $filtered = static fn (): array => [
        Sentinel::reseal(new ResealOptions(Invoice::class, onlyOutdated: true))->resealed,
        Sentinel::reseal(new ResealOptions(Invoice::class, upgradeFormat: true))->resealed,
        Sentinel::reseal(new ResealOptions(Invoice::class, fromKeyId: 'nope'))->resealed,
    ];
    $real = $filtered();
    $fake = Sentinel::fake();

    expect($filtered())->toBe($real)->toBe([0, 0, 0]);

    // A row faked outdated is what onlyOutdated re-seals.
    $fake->fakeStatus(Invoice::query()->firstOrFail(), VerificationStatus::Outdated, 'financial');

    expect(Sentinel::reseal(new ResealOptions(Invoice::class, onlyOutdated: true))->resealed)->toBe(1);
});

it('requires an actor for an acknowledging re-seal outside the console under the fake too (chat review C-12)', function (): void {
    app()->instance(Runtime::class, new Runtime(app(), console: false));
    invoice();
    $acknowledging = static fn (): mixed => Sentinel::reseal(new ResealOptions(Invoice::class, acknowledgeReason: 'reviewed'));

    expect($acknowledging)->toThrow(AcknowledgementDeniedException::class, 'actor');

    Sentinel::fake();

    expect($acknowledging)->toThrow(AcknowledgementDeniedException::class, 'actor');
});

it('knows the keys it generated or imported, with their status and owner (chat review C-25)', function (): void {
    $owner = User::query()->create(['name' => 'Partner']);
    $at = CarbonImmutable::now()->addDay();
    $scenario = static function (string $run) use ($owner, $at): array {
        $generated = Sentinel::keys()->ring('http')->generate(Algorithm::Ed25519, "g-{$run}", activatesAt: $at, owner: $owner);
        $imported = Sentinel::keys()->ring('http')->import("i-{$run}", Algorithm::HmacSha256, PARTNER_SECRET, owner: $owner);
        $listed = array_map(static fn (KeyInfo $key): string => $key->keyId, Sentinel::listKeys('http'));
        $found = Sentinel::findKey('http', "g-{$run}");

        return [
            $generated->info->status->value, $generated->info->canSign, $generated->info->ownerType, $generated->info->ownerId,
            $found?->keyId === "g-{$run}", $found?->status->value, $found?->ownerId,
            Sentinel::findKey('http', "i-{$run}")?->status->value, $imported->ownerId,
            in_array("g-{$run}", $listed, true), in_array("i-{$run}", $listed, true),
            Sentinel::keys()->ring()->generate(Algorithm::HmacSha256, 'env-only', KeyDestination::Config)->info->keyId,
            Sentinel::findKey('default', 'env-only'),
        ];
    };

    $real = $scenario('real');
    Sentinel::fake();

    expect($scenario('fake'))->toBe($real)
        ->and($real[0])->toBe('pending')
        ->and($real[3])->toBe((string) $owner->getKey());
});

it('rotates like production under the fake (chat review C-13)', function (): void {
    $scenario = static function (string $run): array {
        $config = Sentinel::keys()->ring()->rotate();
        Sentinel::keys()->ring('http')->import("own-ed-{$run}", Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate(), signing: true);
        $database = Sentinel::keys()->ring('http')->rotate();
        config()->set('sentinel.keys.rings.default.driver', 'chain');
        config()->set('sentinel.keys.rings.default.drivers', ['database', 'config']);
        app(KeyStoreManager::class)->flush();
        $chain = Sentinel::keys()->ring()->rotate();
        config()->set('sentinel.keys.rings.default.driver', 'config');
        app(KeyStoreManager::class)->flush();

        return [
            $config->current->driver, $config->current->algorithm->value, $config->previous?->keyId, $config->previous?->status->value,
            str_contains((string) $config->envSnippet, 'SENTINEL_PREVIOUS_KEYS="test-default|hmac-sha256|'),
            $database->current->driver, $database->current->algorithm->value, $database->previous?->keyId === "own-ed-{$run}",
            $database->previous?->status->value, $database->envSnippet, Sentinel::findKey('http', "own-ed-{$run}")?->status->value,
            $chain->current->driver, $chain->previous?->keyId, $chain->envSnippet !== null,
        ];
    };

    $real = $scenario('real');
    Sentinel::fake();

    expect($scenario('fake'))->toBe($real)
        ->and($real[0])->toBe('config')
        ->and($real[6])->toBe('ed25519')
        ->and($real[11])->toBe('config');
});

it('refuses to rotate a custom driver\'s key under the fake too (chat review C-13)', function (): void {
    Sentinel::extend('vault', static fn (): KeyStore => new class implements KeyStore
    {
        public function signingKey(): SealingKey
        {
            return new SealingKey('default', 'vault-1', KeyMaterial::fromEncoded(Algorithm::HmacSha256, TestCase::ROOT_KEY), KeyStatus::Active, 'vault');
        }

        public function find(string $keyId): ?SealingKey
        {
            return null;
        }

        public function all(): array
        {
            return [];
        }

        public function supportsWrites(): bool
        {
            return false;
        }
    });
    config()->set('sentinel.keys.rings.default.driver', 'vault');
    Sentinel::fake();

    expect(fn () => Sentinel::keys()->ring()->rotate())->toThrow(KeyDriverException::class, 'custom driver [vault]');
});
