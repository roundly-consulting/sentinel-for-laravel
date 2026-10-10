<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Route as LaravelRoute;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use RoundlyConsulting\Sentinel\Actions\Keys\ImportKeyAction;
use RoundlyConsulting\Sentinel\Actions\Keys\RetireKeyAction;
use RoundlyConsulting\Sentinel\Actions\Seals\AcknowledgeTamperingAction;
use RoundlyConsulting\Sentinel\Actions\Seals\ReadLedgerHistoryAction;
use RoundlyConsulting\Sentinel\Actions\Seals\SealModelAction;
use RoundlyConsulting\Sentinel\Actions\Seals\VerifyModelAction;
use RoundlyConsulting\Sentinel\Concerns\HasSeals;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\Contracts\IdempotencyStore;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssueNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealWhereRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SignedRouteRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\UpdateAndResealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifyRequest;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Definition\SealDefinitionBuilder;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotencyKeyReusedException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResponseUnavailableException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResultException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidIdempotencyKeyException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\NonceRejectedException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Facades\Sentinel as SentinelFacade;
use RoundlyConsulting\Sentinel\Http\Middleware\EnsureIdempotency;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifyHttpSignature;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifySeals;
use RoundlyConsulting\Sentinel\Jobs\Middleware\Idempotent;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Stores\ConfigKeyStore;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Rules\IntactSeal;
use RoundlyConsulting\Sentinel\SealHandle;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Testing\InMemoryIdempotencyStore;
use RoundlyConsulting\Sentinel\Testing\RecordedCall;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;
use RoundlyConsulting\Sentinel\Testing\SentinelTestKeys;
use RoundlyConsulting\Sentinel\Testing\WithSentinelKeys;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Anchors\MemoryAnchor;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Definitions\PartyIdentitySeal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Jobs\ChargeJob;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\InvoiceLine;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides\SafeOverride;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * Phase I exit (plan §11): every documented example runs. Each test mirrors one docs section
 * (the README quick start and the website docs) against the fixtures (the docs' `Invoice` is
 * the fixture invoice, whose `financial` and `identity` seals cover the docs' columns). The
 * drift checks at the end read README.md itself: every facade call, method, class, command,
 * config key and middleware alias it names must exist.
 */
function readme(): string
{
    return (string) file_get_contents(__DIR__.'/../../README.md');
}

it('runs the quick start', function (): void {
    config()->set('sentinel.sealing.allow_suspension', true);
    $existing = Sentinel::withoutSealing(static fn () => Invoice::query()->create(['customer_id' => 1, 'amount' => '5.00']), reason: 'existing rows');

    expect(Artisan::call('sentinel:seal-missing', ['model' => Invoice::class, '--reason' => 'Initial baseline']))->toBe(0)
        ->and(Sentinel::verify($existing)->isIntact())->toBeTrue();

    $invoice = invoice();
    $admin = User::query()->create(['name' => 'Admin']);
    Route::get('/invoices/{invoice}', static fn (Invoice $invoice): string => 'ok')->middleware([SubstituteBindings::class, 'sentinel.verified']);

    expect($invoice->isIntact())->toBeTrue()
        ->and(Sentinel::for($invoice)->verifyOrFail()->isIntact())->toBeTrue()
        ->and($this->get("/invoices/{$invoice->id}")->status())->toBe(200);

    DB::update('UPDATE invoices SET amount = 0 WHERE id = ?', [$invoice->id]);
    $result = Sentinel::for($invoice)->verify();

    expect($result->status)->toBe(VerificationStatus::Tampered)
        ->and($result->reason)->toBe('mac')
        ->and($result->changedAttributes)->toBe(['a:amount'])
        ->and(fn () => $invoice->update(['note' => 'x']))->toThrow(TamperedModelException::class)
        ->and($this->get("/invoices/{$invoice->id}")->status())->toBe(409)
        ->and(Sentinel::for($invoice)->by($admin)->because('INC-88: refund fixed by the DBA')->acknowledge()->acknowledged)->toBeTrue()
        ->and(Artisan::call('sentinel:checkpoint'))->toBe(0)
        ->and(Artisan::call('sentinel:verify', ['--ledger' => true]))->toBe(0)
        ->and(Artisan::call('sentinel:check'))->toBe(0)
        ->and($result->changedColumns())->toBe(['amount']);
});

it('runs the guided installation', function (): void {
    // Publishing is pinned in tests/Install (a sandboxed config/ and database/); here only
    // the command's presence and its next steps.
    expect(Artisan::all())->toHaveKey('sentinel:install')
        ->and(Artisan::all()['sentinel:install']->getDefinition()->hasOption('force'))->toBeTrue();
});

it('compiles the seal declarations', function (): void {
    $class = definedBy(static function ($seals): void {
        $seals->seal('financial')
            ->attributes('customer_id', 'currency', 'amount', 'status', 'paid', 'due_on')
            ->decimal('amount', 2)
            ->computed('lines', static fn ($invoice): array => InvoiceLine::query()->where('invoice_id', $invoice->id)
                ->orderBy('id')->get(['sku', 'quantity'])->toArray())
            ->algorithms(Algorithm::HmacSha256, Algorithm::Ed25519)
            ->scope(static fn ($invoice): string => (string) $invoice->tenant_id)
            ->verifyOnRetrieve(Reaction::Throw);

        $seals->seal('identity')->using(PartyIdentitySeal::class)->lenient();
    });
    $model = $class::query()->create(['number' => 'R-1', 'secret' => 'iban', 'paid' => true]);

    expect(Sentinel::model($class)->seals())->toBe(['financial', 'identity'])
        ->and(Sentinel::verifyAll($model)->allIntact())->toBeTrue()
        ->and($class::query()->findOrFail($model->getKey()))->toBeInstanceOf($class)
        ->and(array_column(Sentinel::model($class)->definition('identity')->manifest(), 0))->toBe(['a:meta', 'a:number', 'a:secret']);
});

it('runs the sealing and writes examples', function (): void {
    config()->set('sentinel.sealing.allow_suspension', true);
    $imported = Sentinel::withoutSealing(fn () => Invoice::query()->create(['number' => 'IMP-1']), reason: 'Legacy import');
    $record = SafeOverride::query()->create(['name' => '  padded  ']);

    expect(Sentinel::verify($imported, 'financial')->status)->toBe(VerificationStatus::Missing)
        ->and(Sentinel::seal($imported)->version)->toBe(1)
        ->and(Sentinel::for($imported, 'identity')->because('adopted')->seal()->version)->toBe(1)
        ->and($imported->seal()->version)->toBe(2)
        ->and($record->name)->toBe('padded')
        ->and(Sentinel::verify($record)->isIntact())->toBeTrue();
});

it('runs the verification examples', function (): void {
    $invoice = invoice();
    $invoices = [$invoice, invoice()];

    expect(Sentinel::for($invoice)->verify()->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::for($invoice, 'identity')->verify()->isIntact())->toBeTrue()
        ->and(Sentinel::verify($invoice, 'financial')->reason)->toBeNull()
        ->and($invoice->isIntact())->toBeTrue()
        ->and($invoice->verifySeal('identity')->isIntact())->toBeTrue()
        ->and(Sentinel::verifyAll($invoice)->allIntact())->toBeTrue()
        ->and(Sentinel::verifyMany($invoices, 'financial')->failures())->toBe([])
        ->and(Sentinel::for($invoice)->verifyOrFail()->changedAttributes)->toBeNull();
});

it('runs the acknowledgement examples', function (): void {
    $invoice = invoice();
    $admin = User::query()->create(['name' => 'Admin']);

    $intact = Sentinel::for($invoice)->by($admin)->because('INC-88: refund fixed by the DBA')->acknowledge();

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '1.00']);

    expect($intact->acknowledged)->toBeFalse()
        ->and($intact->before->status)->toBe(VerificationStatus::Intact)
        ->and($invoice->acknowledgeTampering('INC-88: refund fixed by the DBA', $admin)->acknowledged)->toBeTrue()
        ->and(Sentinel::for($invoice)->current()?->version)->toBe(2)
        ->and(Sentinel::for($invoice)->history(10))->toHaveCount(2)
        ->and(Sentinel::for($invoice)->definition()->name)->toBe('financial')
        ->and(Sentinel::for($invoice)->name())->toBe('financial')
        ->and(Sentinel::for($invoice, 'identity')->unseal('archived'))->toBeTrue();
});

it('runs the bulk examples', function (): void {
    $admin = User::query()->create(['name' => 'Admin']);
    $draft = invoice(['status' => 'draft']);
    config()->set('sentinel.sealing.allow_suspension', true);
    $imported = Sentinel::withoutSealing(fn () => invoice(['status' => 'draft']), reason: 'import');
    $seals = Sentinel::model(Invoice::class);

    expect($seals->scan()->hasFindings())->toBeTrue()
        ->and($seals->unsealedQuery()->count())->toBe(1)
        ->and($seals->sealMissing(reason: 'Initial baseline')->resealed)->toBe(2)
        ->and($seals->reseal()->skipped)->toBe(0);

    DB::table('invoices')->where('id', $imported->id)->update(['amount' => '0.00']);

    expect($seals->reseal(acknowledgeReason: 'INC-90')->acknowledged)->toBe(1)
        ->and($seals->resealWhere(fn ($query) => $query->where('status', 'draft'), reason: 'INC-91', actor: $admin)->skipped)->toBe(4)
        ->and($seals->updateAndReseal(
            fn ($query) => $query->where('status', 'draft'), ['currency' => 'USD'], reason: 'FIN-12 currency migration', actor: $admin,
        )->resealed)->toBe(2)
        ->and($draft->refresh()->currency)->toBe('USD')
        ->and($seals->seals())->toBe(['financial', 'identity']);

    $rows = [];
    $tenant = $seals->scan(where: fn ($query) => $query->where('tenant_id', 7), progress: function (int $processed) use (&$rows): void {
        $rows[] = $processed;
    });

    expect($tenant->scanned)->toBe(0)
        ->and($rows)->toBe([]);
});

it('loads a tampered model for the acknowledgement screen', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('financial')->attributes('amount')->verifyOnRetrieve(Reaction::Throw));
    $invoice = $class::query()->create(['amount' => '5.00']);
    DB::table('invoices')->where('id', $invoice->getKey())->update(['amount' => '0.00']);

    Route::bind('tamperedInvoice', fn (string $id) => Sentinel::model($class)->findOrFail($id));
    Route::post('/admin/invoices/{tamperedInvoice}/acknowledge', static fn ($tamperedInvoice): string => Sentinel::acknowledge($tamperedInvoice, 'INC-7')->acknowledged ? 'ok' : 'no')
        ->middleware(SubstituteBindings::class);

    expect($this->post("/admin/invoices/{$invoice->getKey()}/acknowledge")->getContent())->toBe('ok');
});

it('runs the ledger examples', function (): void {
    $invoice = invoice();
    config()->set('sentinel.ledger.anchors', 'cache');

    $checkpoint = Sentinel::ledger()->checkpoint();
    $report = Sentinel::ledger()->verify();

    expect($checkpoint?->seq)->toBe(1)
        ->and($report->clean())->toBeTrue()
        ->and($report->findings)->toBe([])
        ->and(Sentinel::ledger()->history($invoice))->toHaveCount(1)
        ->and(Sentinel::ledger()->head()?->seq)->toBe(1)
        ->and(Sentinel::ledger()->anchors())->toBe(['cache']);
});

it('runs the middleware, rule, macro and scope examples', function (): void {
    $invoice = invoice();
    $line = $invoice->lines()->create(['sku' => 'A-1', 'quantity' => 1]);
    Sentinel::seal($invoice);   // the computed `lines` changed: re-seal the owner
    Route::put('/invoices/{invoice}/lines/{line}', static fn (Invoice $invoice, InvoiceLine $line): string => 'ok')
        ->middleware([SubstituteBindings::class, 'sentinel.verified:invoice@financial']);
    $validator = Validator::make(['invoice_id' => $invoice->id], ['invoice_id' => ['required', new IntactSeal(Invoice::class, seal: 'financial')]]);
    config()->set('sentinel.sealing.allow_suspension', true);
    Sentinel::withoutSealing(fn () => invoice(), reason: 'import');

    expect($this->put("/invoices/{$invoice->id}/lines/{$line->id}")->status())->toBe(200)
        ->and($validator->passes())->toBeTrue()
        ->and(Invoice::query()->withSeals()->get()->verifySeals()->allIntact())->toBeFalse()
        ->and(Invoice::query()->whereSealed()->count())->toBe(1)
        ->and(Invoice::query()->whereNotSealed('identity')->get())->toHaveCount(1);
});

it('runs the typed middleware examples', function (): void {
    config()->set('sentinel.signatures.profiles.partners', config('sentinel.signatures.profiles.default'));
    $invoice = invoice();
    Route::put('/invoices/{invoice}', static fn (Invoice $invoice): string => 'ok')->middleware([SubstituteBindings::class, VerifySeals::using('invoice@financial')]);
    Route::post('/orders', static fn (): string => 'ok')->middleware(EnsureIdempotency::required(ttl: 3600));
    Route::post('/partner/events', static fn (): string => 'ok')->middleware(VerifyHttpSignature::profile('partners'));

    expect($this->put("/invoices/{$invoice->id}")->status())->toBe(200)
        ->and($this->postJson('/orders')->status())->toBe(400)
        ->and($this->postJson('/partner/events')->status())->toBe(401);
});

it('runs the idempotency examples', function (): void {
    $runs = 0;
    Route::post('/orders', static function () use (&$runs) {
        return response()->json(['order' => ++$runs], 201);
    })->middleware(['auth', 'sentinel.idempotent:required']);
    $this->actingAs(User::query()->create(['name' => 'Buyer']));
    $order = static fn () => test()->postJson('/orders', ['sku' => 'A-1'], ['Idempotency-Key' => '"8e03978e-40d5-43e8-bc93-6894a57f9324"']);

    $first = $order();
    $repeat = $order();

    expect($first->status())->toBe(201)
        ->and($repeat->json('order'))->toBe(1)
        ->and($repeat->headers->get('Idempotent-Replayed'))->toBe('true')
        ->and($this->postJson('/orders', ['sku' => 'A-1'])->status())->toBe(400);

    $sent = null;
    Http::fake(static function (ClientRequest $request) use (&$sent) {
        $sent = $request;

        return Http::response('ok');
    });
    Http::withIdempotencyKey()->post('https://api.example.com/orders', ['sku' => 'A-1']);

    expect($sent?->header('Idempotency-Key')[0] ?? '')->toMatch('/^"[0-9a-f-]{36}"$/');

    $charges = 0;
    $charge = static function () use (&$charges): array {
        return ['charge' => 'ch_'.++$charges];
    };
    $result = Sentinel::idempotency()->run('charge:42', scope: 'billing', callback: $charge);
    $again = Sentinel::idempotency()->run('charge:42', scope: 'billing', callback: $charge);

    expect($result->value)->toBe(['charge' => 'ch_1'])
        ->and($result->replayed)->toBeFalse()
        ->and($again->replayed)->toBeTrue()
        ->and($again->value)->toBe($result->value)
        ->and(Sentinel::idempotency()->forget('charge:42', scope: 'billing'))->toBeTrue()
        ->and(fn () => Sentinel::idempotency()->run('pdf:1', scope: 'billing', callback: static fn (): string => "%PDF\xB5"))->toThrow(IdempotentResultException::class)
        ->and(fn () => Sentinel::idempotency()->run('pdf:1', scope: 'billing', callback: static fn (): string => "%PDF\xB5"))->toThrow(IdempotentResponseUnavailableException::class);

    ChargeJob::$runs = 0;
    ChargeJob::dispatch('evt_1');
    ChargeJob::dispatch('evt_1');

    expect(ChargeJob::$runs)->toBe(1)
        ->and((new ChargeJob('evt_2'))->middleware()[0])->toBeInstanceOf(Idempotent::class);
});

it('runs the nonce and single-use URL examples', function (): void {
    $user = User::query()->create(['name' => 'u']);
    $nonce = Sentinel::nonces()->issue('password-reset', ttl: 900, subject: $user);
    $token = $nonce->value;

    expect(strlen($nonce->value))->toBe(43)
        ->and(Sentinel::nonces()->consume('password-reset', $token, $user))->toBeTrue()
        ->and(fn () => Sentinel::nonces()->consumeOrFail('password-reset', $token, $user))->toThrow(NonceRejectedException::class);

    Route::get('/exports/{export}', static fn (string $export): string => 'export '.$export)->name('exports.download')->middleware('sentinel.single-use');
    $url = Sentinel::nonces()->signedRoute('exports.download', ['export' => 7], ttl: 600);

    expect($this->get($url)->status())->toBe(200)
        ->and($this->get($url)->status())->toBe(403);
});

it('runs the message signature examples', function (): void {
    $partner = User::query()->create(['name' => 'ACME']);
    $key = Sentinel::keys()->ring('http')->generate(Algorithm::Ed25519, keyId: 'acme-2026-10', owner: $partner);
    // Our own verifier stands in for the partner's: it must accept a key this application signs with.
    config()->set('sentinel.signatures.profiles.default.accept_signing_keys', true);
    $verified = null;
    Route::post('/partner/events', static function (Request $request) use (&$verified): string {
        $verified = $request->attributes->get('sentinel.signature');

        return 'ok';
    })->middleware('sentinel.signed');
    $sent = null;
    Http::fake(static function (ClientRequest $request) use (&$sent) {
        $sent = $request->toPsrRequest();

        return Http::response('ok');
    });

    Http::withSignature('acme-2026-10')->post('https://partner.example/partner/events', ['event' => 'paid']);
    $request = received($sent);
    $response = $this->createTestResponse(app(Kernel::class)->handle($request), $request);

    expect($key->publicKey)->toStartWith('base64:')
        ->and($response->status())->toBe(200)
        ->and($verified)->toBeInstanceOf(VerifiedSignature::class)
        ->and($verified?->keyId)->toBe('acme-2026-10')
        ->and((string) $verified?->ownerId)->toBe((string) $partner->id)
        ->and(Sentinel::signatures()->contentDigest('{"hello": "world"}'))->toBe('sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:');
});

it('runs the partner import and signature reader examples', function (): void {
    $partner = User::query()->create(['name' => 'ACME']);
    $partnerKey = KeyMaterial::generate(Algorithm::Ed25519);
    partnerRing('acme-2026-10', Algorithm::Ed25519, (string) $partnerKey->encodedPrivate());
    $request = received(Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/partner/events', ['Content-Type' => 'application/json'], '{"event":"paid"}'), 'acme-2026-10'));
    config()->set('sentinel.keys.rings.http.driver', 'database');
    config()->set('sentinel.keys.rings.http.key', null);
    app(KeyStoreManager::class)->flush();
    $partnerPublicKeyPem = "-----BEGIN PUBLIC KEY-----\n".base64_encode("\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".base64_decode(substr((string) $partnerKey->encodedPublic(), 7)))."\n-----END PUBLIC KEY-----\n";

    Sentinel::keys()->ring('http')->import('acme-2026-10', Algorithm::Ed25519, $partnerPublicKeyPem, owner: $partner);

    $read = [];
    Route::post('/partner/events', static function (Request $request) use (&$read): string {
        $read = [Sentinel::signatures()->current($request)?->keyId, Sentinel::signatures()->owner($request)?->getKey()];

        return 'ok';
    })->middleware('sentinel.signed');

    expect(app(Kernel::class)->handle($request)->getStatusCode())->toBe(200)
        ->and($read)->toBe(['acme-2026-10', $partner->id])
        ->and(Artisan::all())->toHaveKey('sentinel:key:import');
});

it('runs the key management examples', function (): void {
    $partner = User::query()->create(['name' => 'ACME']);
    $admin = User::query()->create(['name' => 'Admin']);
    $pem = (string) base64_decode(substr((string) KeyMaterial::generate(Algorithm::EcdsaP256Sha256)->encodedPublic(), 7), true);
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'acme-2025-10');   // the ring's older, signing key

    $ring = Sentinel::keys()->ring('http');
    $pending = $ring->generate(Algorithm::Ed25519, keyId: 'acme-2026-11', activatesAt: now()->addWeek());
    $imported = $ring->import('acme-2026-10', Algorithm::EcdsaP256Sha256, $pem, owner: $partner);
    $rotation = $ring->rotate();
    $revoked = $ring->revoke('acme-2026-10', reason: 'Partner offboarded', actor: $admin);
    $retired = $ring->retire('acme-2025-10');
    $lines = Sentinel::keys()->ring()->generate(Algorithm::HmacSha256, destination: KeyDestination::Config)->envSnippet;

    expect(Sentinel::keys()->rings())->toBe(['default', 'http'])
        ->and(Sentinel::keys()->all())->toHaveCount(5)
        ->and(Sentinel::keys()->ring()->current()->keyId)->toBe('test-default')
        ->and($ring->name())->toBe('http')
        ->and($ring->find('acme-2026-10')?->status)->toBe(KeyStatus::Revoked)
        ->and($ring->all())->toHaveCount(4)
        ->and($pending->info->status)->toBe(KeyStatus::Pending)
        ->and($imported->status)->toBe(KeyStatus::VerifyOnly)
        ->and($rotation->previous?->keyId)->toBe('acme-2025-10')
        ->and($rotation->current->status)->toBe(KeyStatus::Active)
        ->and($revoked->status)->toBe(KeyStatus::Revoked)
        ->and($retired->status)->toBe(KeyStatus::Retired)
        ->and($lines)->toContain('SENTINEL_KEY_ID=')
        ->and(Sentinel::keys()->ring()->all())->toHaveCount(1)   // the config destination stored nothing
        // revoke() and retire() change database keys only
        ->and(fn () => Sentinel::keys()->ring()->revoke('test-default', reason: 'Compromised'))->toThrow(KeyDriverException::class, 'comes from configuration, not the database')
        ->and(fn () => Sentinel::keys()->ring()->retire('test-default'))->toThrow(KeyDriverException::class, 'comes from configuration, not the database');
});

it('runs the flat key examples', function (): void {
    $partner = User::query()->create(['name' => 'ACME']);
    $admin = User::query()->create(['name' => 'Admin']);
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'acme-2025-10');

    $key = Sentinel::generateKey(new GenerateKeyRequest('http', Algorithm::Ed25519, keyId: 'acme-2027-01', owner: $partner));
    $rotation = Sentinel::rotateKey(new RotateKeyRequest('http'));
    $revoked = Sentinel::revokeKey(new RevokeKeyRequest('http', 'acme-2027-01', 'Partner offboarded', $admin));
    $retired = Sentinel::retireKey('http', 'acme-2025-10');

    expect($key->info->keyId)->toBe('acme-2027-01')
        ->and($key->publicKey)->toStartWith('base64:')
        ->and($rotation->current->status)->toBe(KeyStatus::Active)
        ->and($revoked->status)->toBe(KeyStatus::Revoked)
        ->and($retired->status)->toBe(KeyStatus::Retired)
        ->and(Sentinel::listKeys('http'))->toHaveCount(3)
        ->and(Sentinel::listKeys())->toHaveCount(4)
        ->and(Sentinel::findKey('http', 'acme-2027-01')?->status)->toBe(KeyStatus::Revoked)
        ->and(Sentinel::currentKey()->keyId)->toBe('test-default');
});

it('runs the extension examples', function (): void {
    $manager = Sentinel::extend('vault', fn (Container $app, string $ring, array $config): KeyStore => new ConfigKeyStore(Settings::ring($ring), [], Clock::now()));
    Sentinel::extendAnchor('s3-lock', fn (Container $app, array $config): Anchor => new class implements Anchor
    {
        public function name(): string
        {
            return 's3-lock';
        }

        public function publish(AnchorPayload $payload): void {}

        public function latest(string $connection): ?AnchorPayload
        {
            return null;
        }
    });
    config()->set('sentinel.ledger.anchors', 's3-lock');
    config()->set('sentinel.keys.rings.default.driver', 'vault');
    invoice();

    expect($manager)->toBeInstanceOf(SentinelManager::class)
        ->and(Sentinel::checkpoint()?->anchors[0]->published)->toBeTrue()
        ->and(Sentinel::keys()->ring()->current()->keyId)->toBe('test-default');
});

it('runs the health check example', function (): void {
    invoice();

    expect(Sentinel::sealables())->toBe([Invoice::class]);

    $report = Sentinel::check();

    expect($report->failed())->toBeFalse()
        ->and($report->failures())->toBe([])
        ->and(array_map(static fn ($check): string => $check->name, $report->warnings()))->toBe(['anchors'])
        ->and(Artisan::call('sentinel:check', ['--strict' => true]))->toBe(1);
});

it('runs the event listener example', function (): void {
    $invoice = invoice();
    $seen = [];
    Event::listen(function (TamperDetected $event) use (&$seen): void {
        $seen = [$event->model()?->getKey(), $event->changedColumns()];
    });
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);

    Sentinel::verify($invoice);

    expect($seen)->toBe([$invoice->id, ['amount']]);
});

it('runs the examples without the facade', function (): void {
    $consumer = new class(app(SentinelManager::class))
    {
        public function __construct(private SentinelManager $sentinel) {}

        public function __invoke(Invoice $invoice, User $admin): void
        {
            $this->sentinel->for($invoice)->by($admin)->because('Ticket #412: corrected VAT via SQL')->acknowledge();
        }
    };
    $invoice = invoice();
    $admin = User::query()->create(['name' => 'Admin']);
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '1.00']);

    $consumer($invoice, $admin);
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '2.00']);
    $result = app(AcknowledgeTamperingAction::class)->execute(new AcknowledgeRequest(
        model: $invoice, seal: 'financial', reason: 'Ticket #412: corrected VAT via SQL', actor: $admin,
    ));

    expect($result->acknowledged)->toBeTrue()
        ->and(Sentinel::for($invoice)->history())->toHaveCount(3);

    $partner = User::query()->create(['name' => 'ACME']);
    $pem = (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPublic();

    Sentinel::keys()->ring('http')->import('acme-2026-10', Algorithm::Ed25519, $pem, owner: $partner);
    $imported = app(ImportKeyAction::class)->execute(new ImportKeyRequest('http', 'acme-2026-11', Algorithm::Ed25519, $pem, owner: $partner));
    $sealed = app(SealModelAction::class)->execute(new SealRequest($invoice, reason: 'INC-1'));
    Sentinel::for($invoice)->because('INC-1')->seal();

    expect($imported->status)->toBe(KeyStatus::VerifyOnly)
        ->and($sealed->seal)->toBe('financial');
});

it('runs the testing example', function (): void {
    $invoice = invoice();
    Route::get('/invoices/{invoice}', static fn (Invoice $invoice): string => 'ok')->middleware([SubstituteBindings::class, 'sentinel.verified']);

    $fake = Sentinel::fake();
    $fake->fakeStatus($invoice, VerificationStatus::Tampered, 'financial', changed: ['a:amount']);

    $this->get("/invoices/{$invoice->id}")->assertStatus(409);

    Sentinel::assertVerified($invoice);
    Sentinel::assertNothingAcknowledged();

    $fake->fakeLedgerFindings(new LedgerFinding(LedgerFindingKind::ChainBroken, 3, 17, Invoice::class, 1, 'financial', 'previous digest', 'mysql'));
    $this->artisan('sentinel:verify --ledger --allow-empty')->assertExitCode(1);
});

it('runs the real-keys testing example', function (): void {
    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    SentinelTestKeys::install(app(), Algorithm::Ed25519, rings: ['default', 'http']);

    expect(Sentinel::verify(invoice())->isIntact())->toBeTrue()
        ->and(Sentinel::keys()->ring('http')->current()->keyId)->toBe('test-http')
        ->and(trait_exists(WithSentinelKeys::class))->toBeTrue();
});

it('runs the verification result and action examples', function (): void {
    $invoice = invoice();
    $intact = app(VerifyModelAction::class)->execute(new VerifyRequest($invoice, 'financial', checkLedger: false));

    DB::table('invoice_lines')->insert(['invoice_id' => $invoice->id, 'sku' => 'B-2', 'quantity' => 3]);
    $drifted = Sentinel::verify($invoice, 'financial');

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);
    $tampered = Sentinel::verify($invoice, 'financial');

    expect($intact->isIntact())->toBeTrue()
        ->and($drifted->onlyComputedChanged())->toBeTrue()
        ->and($drifted->changedComputed())->toBe(['lines'])
        ->and($tampered->onlyComputedChanged())->toBeFalse()
        ->and($tampered->toArray())->toMatchArray(['status' => 'tampered', 'reason' => 'mac', 'seal' => 'financial', 'intact' => false])
        ->and(array_keys($tampered->toArray()))->toBe(['status', 'reason', 'sealable_type', 'sealable_id', 'seal', 'version', 'ledger_version', 'ring', 'key_id', 'algorithm', 'sealed_at', 'changed_attributes', 'context', 'intact']);
});

it('runs the flat per-model examples', function (): void {
    $invoice = invoice();
    $id = $invoice->id;
    $admin = User::query()->create(['name' => 'Admin']);
    DB::table('invoices')->where('id', $id)->update(['amount' => '1.00']);

    expect(Sentinel::acknowledge($invoice, 'INC-88: refund fixed by the DBA', $admin, 'financial')->acknowledged)->toBeTrue()
        ->and(Sentinel::unseal($invoice, 'GDPR erasure #12', $admin, 'identity'))->toBeTrue()
        ->and(Sentinel::ledgerHistory($invoice, 'financial', limit: 20))->toHaveCount(2)
        ->and(Sentinel::currentSeal($invoice)?->version)->toBe(2)
        ->and(Sentinel::withoutVerification(fn () => Invoice::query()->find($id))?->is($invoice))->toBeTrue();
});

it('runs the flat bulk examples', function (): void {
    $admin = User::query()->create(['name' => 'Admin']);
    $draft = invoice(['status' => 'draft']);
    config()->set('sentinel.sealing.allow_suspension', true);
    Sentinel::withoutSealing(fn () => invoice(['tenant_id' => 7]), reason: 'import');

    $scan = Sentinel::scan(new ScanOptions([Invoice::class], seal: 'financial', limit: 10_000, checkSchema: true));
    $baseline = Sentinel::sealMissing(new BaselineOptions(Invoice::class, null, 'Initial baseline'));

    expect($scan->count(VerificationStatus::Missing))->toBe(1)
        ->and($baseline->resealed)->toBe(2)
        ->and(Sentinel::reseal(new ResealOptions(Invoice::class, onlyOutdated: true))->resealed)->toBe(0)
        ->and(Sentinel::reseal(new ResealOptions(Invoice::class, upgradeFormat: true))->resealed)->toBe(0)
        ->and(Sentinel::resealWhere(new ResealWhereRequest(Invoice::class, fn ($query) => $query->where('tenant_id', 7), 'INC-91', $admin))->failed)->toBe(0)
        ->and(Sentinel::updateAndReseal(new UpdateAndResealRequest(Invoice::class, fn ($query) => $query->where('status', 'draft'), ['currency' => 'EUR'], 'FIN-12', $admin))->resealed)->toBe(1)
        ->and($draft->refresh()->currency)->toBe('EUR');
});

it('runs the flat ledger examples', function (): void {
    $anchor = MemoryAnchor::install();
    invoice();

    $checkpoint = Sentinel::checkpoint(new CheckpointOptions(connection: null, batchSize: 500));
    $payload = $anchor->latest(DB::getDefaultConnection());
    config()->set('sentinel.ledger.anchors', '');   // a write-only anchor: compare the copy you kept
    $report = Sentinel::verifyLedger(new LedgerVerifyOptions(manualAnchor: $payload));

    expect($checkpoint?->seq)->toBe(1)
        ->and(Sentinel::checkpoint(new CheckpointOptions(connection: null, batchSize: 500)))->toBeNull()
        ->and(Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false))->clean())->toBeTrue()
        ->and($payload)->toBeInstanceOf(AnchorPayload::class)
        ->and($report->clean())->toBeTrue()
        ->and($report->anchorsChecked)->toBe(1)
        ->and(Sentinel::ledgerHead()?->seq)->toBe(1)
        ->and(Sentinel::anchors())->toBe([]);
});

it('runs the validation rule examples', function (): void {
    $invoice = invoice(['number' => 'INV-42']);
    $rules = static fn (): array => [
        'invoice_id' => ['required', new IntactSeal(Invoice::class, seal: 'financial')],
        'invoice_number' => ['required', new IntactSeal(Invoice::class, seal: 'financial', column: 'number')],
    ];

    expect(Validator::make(['invoice_id' => $invoice->id, 'invoice_number' => 'INV-42'], $rules())->passes())->toBeTrue()
        ->and(Validator::make(['invoice_id' => $invoice->id, 'invoice_number' => 'INV-0'], $rules())->errors()->first('invoice_number'))->toBe('The selected invoice number is invalid.')
        ->and(fn () => new IntactSeal(Invoice::class, column: 'number; drop table'))->toThrow(SealingMisconfiguredException::class)
        ->and(Invoice::query()->get()->verifySeals('financial')->allIntact())->toBeTrue();

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

    expect(Validator::make(['invoice_number' => 'INV-42'], $rules())->errors()->first('invoice_number'))->toBe('The selected invoice number failed an integrity check.');
});

it('runs the idempotency argument and flat examples', function (): void {
    $charge = static fn (): array => ['charge' => 'ch_7'];
    $result = Sentinel::runIdempotent(new IdempotentCall('charge:7', 'billing', $charge, 'order:7:10.50', 3600));

    expect($result->value)->toBe(['charge' => 'ch_7'])
        ->and(fn () => Sentinel::idempotency()->run('charge:7', scope: '', callback: $charge))->toThrow(InvalidIdempotencyKeyException::class)
        ->and(fn () => Sentinel::idempotency()->run('charge:7', scope: 'billing', callback: $charge, ttl: 59))->toThrow(InvalidIdempotencyKeyException::class)
        ->and(fn () => Sentinel::idempotency()->run('charge:7', scope: 'billing', callback: $charge, fingerprint: 'order:7:99.00'))->toThrow(IdempotencyKeyReusedException::class)
        ->and(fn () => Sentinel::idempotency()->forget('charge:7', scope: ''))->toThrow(InvalidIdempotencyKeyException::class)
        ->and(Sentinel::forgetIdempotencyKey('charge:7', 'billing'))->toBeTrue();
});

it('runs the flat nonce, single-use URL and prune examples', function (): void {
    $user = User::query()->create(['name' => 'u']);
    Route::get('/exports/{export}', static fn (string $export): string => 'export '.$export)->name('exports.download')->middleware('sentinel.single-use');

    $nonce = Sentinel::issueNonce(new IssueNonceRequest('password-reset', ttl: 900, subject: $user));
    $url = Sentinel::signedRoute(new SignedRouteRequest('exports.download', ['export' => 7], ttl: 600));

    expect(Sentinel::consumeNonce(new ConsumeNonceRequest('password-reset', $nonce->value, $user)))->toBeTrue()
        ->and(Sentinel::consumeNonce(new ConsumeNonceRequest('password-reset', $nonce->value, $user)))->toBeFalse()
        ->and($this->get($url)->status())->toBe(200);

    $this->travel(1)->hours();
    $counted = Sentinel::prune(new PruneOptions(idempotency: true, nonces: true, dryRun: true));

    expect($counted->nonces)->toBeGreaterThan(0)
        ->and(Sentinel::prune(new PruneOptions(idempotency: true, nonces: true, dryRun: true))->nonces)->toBe($counted->nonces)
        ->and(Sentinel::prune()->nonces)->toBe($counted->nonces);
});

it('runs the signing options and signature reader examples', function (): void {
    $partner = User::query()->create(['name' => 'ACME']);
    Sentinel::keys()->ring('http')->generate(Algorithm::Ed25519, keyId: 'acme-2027-01', owner: $partner);
    // Our own verifier stands in for the partner's (which holds the public half): it must
    // accept a key this application signs with.
    config()->set('sentinel.signatures.profiles.partners', [...config('sentinel.signatures.profiles.default'), 'require_nonce' => false, 'accept_signing_keys' => true]);
    $sent = null;
    Http::fake(static function (ClientRequest $request) use (&$sent) {
        $sent = $request->toPsrRequest();

        return Http::response('ok');
    });

    Http::withSignature('acme-2027-01', new SigningOptions(expiresIn: 60, tag: 'acme', includeAlg: true))
        ->post('https://partner.example/events', ['event' => 'paid']);

    $input = $sent?->getHeaderLine('Signature-Input') ?? '';
    $psrRequest = new PsrRequest('POST', 'https://api.example.com/partner/events', ['Content-Type' => 'application/json'], '{"event":"paid"}');
    $signed = Sentinel::signatures()->sign($psrRequest, 'acme-2027-01', new SigningOptions(
        components: ['@method', '@authority', '@path', 'content-digest'],
        digest: DigestAlgorithm::Sha512,
        nonce: false,
    ));
    $signature = Sentinel::signatures()->verify(received($signed), 'partners');

    expect($input)->toContain(';expires=')->toContain(';tag="acme"')->toContain(';alg="ed25519"')->toContain(';nonce=')
        ->and($signed->getHeaderLine('Content-Digest'))->toStartWith('sha-512=:')
        ->and($signed->getHeaderLine('Signature-Input'))->not->toContain('nonce=')
        ->and([$signature->label, $signature->ring, $signature->keyId, $signature->algorithm, $signature->expires, $signature->nonce, $signature->tag, $signature->components])
        ->toBe(['sig1', 'http', 'acme-2027-01', Algorithm::Ed25519, null, null, null, ['@method', '@authority', '@path', 'content-digest']])
        ->and($signature->created)->toBeGreaterThan(0)
        ->and([$signature->ownerType, (string) $signature->ownerId])->toBe([$partner->getMorphClass(), (string) $partner->id])
        ->and(Sentinel::verifyRequestSignature(received($signed), 'partners')->keyId)->toBe('acme-2027-01')
        ->and(Sentinel::signRequest($psrRequest, 'acme-2027-01', new SigningOptions(nonce: false))->hasHeader('Signature'))->toBeTrue()
        ->and(fn () => Sentinel::verifyResponseSignature(new PsrResponse(200), 'partners'))->toThrow(HttpSignatureException::class)
        ->and(fn () => Sentinel::signatures()->verify(received($psrRequest), 'partners'))->toThrow(HttpSignatureException::class);
});

it('runs the plain-argument action examples', function (): void {
    $invoice = invoice();
    Sentinel::seal($invoice);
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'acme-2025-10');

    expect(app(ReadLedgerHistoryAction::class)->execute($invoice, 'financial', 20))->toHaveCount(2)
        ->and(app(ReadLedgerHistoryAction::class)->execute($invoice, 'financial', 0))->toHaveCount(1)   // limit 1–1000
        ->and(app(RetireKeyAction::class)->execute('http', 'acme-2025-10')->status)->toBe(KeyStatus::Retired);
});

it('runs the recorded-call example', function (): void {
    $invoice = invoice();
    $fake = Sentinel::fake();

    Sentinel::verify($invoice, 'financial');
    $call = $fake->recorded('verify')[0];

    expect($call)->toBeInstanceOf(RecordedCall::class)
        ->and([$call->method, $call->arguments])->toBe(['verify', [$invoice, 'financial']])
        ->and($call->result)->toBeInstanceOf(VerificationResult::class);
});

it('runs the in-memory store example', function (): void {
    $this->app->instance(IdempotencyStore::class, new InMemoryIdempotencyStore);

    expect(Sentinel::idempotency()->run('job:1', 'jobs', static fn (): int => 1)->value)->toBe(1)
        ->and(Sentinel::idempotency()->run('job:1', 'jobs', static fn (): int => 2)->replayed)->toBeTrue()
        ->and(IdempotencyKey::query()->count())->toBe(0);
});

// ── drift checks: everything the README names exists ────────────────────────────
//
// The README is slim — install, one example, a link to the website docs — so it is checked
// for truth, not completeness (the docs carry the full API). Each check first proves it
// found something.

it('names only facade methods that exist', function (): void {
    preg_match_all('/Sentinel::([a-zA-Z]+)\(/', readme(), $matches);
    $names = array_values(array_unique($matches[1]));

    expect($names)->not->toBeEmpty();

    foreach ($names as $name) {
        expect(method_exists(SentinelManager::class, $name) || method_exists(SentinelFake::class, $name) || method_exists(SentinelFacade::class, $name))->toBeTrue("Sentinel::{$name}() is not a method");
    }
});

it('calls only methods the package has', function (): void {
    preg_match_all('/```php\n(.*?)```/s', readme(), $blocks);
    preg_match_all('/->([a-zA-Z]+)\(/', implode("\n", $blocks[1]), $matches);
    $called = array_values(array_unique($matches[1]));
    $surface = [SentinelManager::class, SealHandle::class, SealBuilder::class, SealDefinitionBuilder::class, HasSeals::class, LaravelRoute::class, Model::class];

    $missing = array_values(array_filter($called, static function (string $method) use ($surface): bool {
        foreach ($surface as $class) {
            if (method_exists($class, $method)) {
                return false;
            }
        }

        return true;
    }));

    expect(count($called))->toBeGreaterThanOrEqual(8)
        ->and($missing)->toBe([]);
});

it('imports only classes that exist', function (): void {
    preg_match_all('/^use (RoundlyConsulting\\\\Sentinel\\\\[A-Za-z\\\\]+);$/m', readme(), $matches);

    expect($matches[1])->not->toBeEmpty();

    foreach (array_unique($matches[1]) as $class) {
        expect(class_exists($class) || interface_exists($class) || trait_exists($class) || enum_exists($class))->toBeTrue("{$class} does not exist");
    }
});

/**
 * Chat review C-30: a block pasted into a namespaced file must not lose its parent class.
 */
it('imports every class a block extends or implements', function (): void {
    preg_match_all('/```php\n(.*?)```/s', readme(), $blocks);
    $checked = 0;

    foreach ($blocks[1] as $block) {
        preg_match_all('/\b(?:extends|implements)\s+([\w\x5C]+(?:\s*,\s*[\w\x5C]+)*)/', $block, $declared);

        foreach ($declared[1] as $list) {
            foreach (array_map(trim(...), explode(',', $list)) as $name) {
                $checked++;

                expect(str_starts_with($name, '\\') || preg_match('/^use [\w\x5C]+\x5C'.preg_quote($name, '/').';$/m', $block) === 1)
                    ->toBeTrue("the README uses {$name} without importing it");
            }
        }
    }

    expect($checked)->toBeGreaterThanOrEqual(2);
});

it('names only commands that exist', function (): void {
    preg_match_all('/\b(sentinel:[a-z][a-z:-]*[a-z])/', readme(), $matches);

    expect($matches[1])->not->toBeEmpty();

    foreach (array_unique($matches[1]) as $command) {
        expect(Artisan::all())->toHaveKey($command);
    }
});

it('names only configuration keys and middleware aliases that exist', function (): void {
    preg_match_all('/`sentinel\.([a-z_.]+)`/', readme(), $keys);
    preg_match_all("/'(sentinel\\.(?:verified|idempotent|signed|single-use))'/", readme(), $aliases);

    expect($keys[1])->not->toBeEmpty()
        ->and($aliases[1])->not->toBeEmpty();

    foreach (array_unique($keys[1]) as $key) {
        expect(config()->has("sentinel.{$key}"))->toBeTrue("sentinel.{$key} is not a configuration key");
    }

    foreach (array_unique($aliases[1]) as $alias) {
        expect(app('router')->getMiddleware())->toHaveKey($alias);
    }
});
