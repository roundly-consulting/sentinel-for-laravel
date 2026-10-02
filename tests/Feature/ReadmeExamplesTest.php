<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use RoundlyConsulting\Sentinel\Actions\Keys\ImportKeyAction;
use RoundlyConsulting\Sentinel\Actions\Seals\AcknowledgeTamperingAction;
use RoundlyConsulting\Sentinel\Actions\Seals\SealModelAction;
use RoundlyConsulting\Sentinel\Contracts\Anchor;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResponseUnavailableException;
use RoundlyConsulting\Sentinel\Exceptions\IdempotentResultException;
use RoundlyConsulting\Sentinel\Exceptions\NonceRejectedException;
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
use RoundlyConsulting\Sentinel\Rules\IntactSeal;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;
use RoundlyConsulting\Sentinel\Testing\SentinelTestKeys;
use RoundlyConsulting\Sentinel\Testing\WithSentinelKeys;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Definitions\PartyIdentitySeal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Jobs\ChargeJob;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\InvoiceLine;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Overrides\SafeOverride;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * Phase I exit (plan §11): every README example runs. Each test mirrors one README section
 * against the fixtures (the README's `Invoice` is the fixture invoice, whose `financial` and
 * `identity` seals cover the README's columns). The drift checks at the end read README.md
 * itself: every facade call, class, command option, config key, env variable, middleware
 * alias, event and fake assertion it names must exist.
 */
function readme(): string
{
    return (string) file_get_contents(__DIR__.'/../../README.md');
}

it('runs the quick start', function (): void {
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
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'acme-2025-10');
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'acme-2026-10');

    expect(Sentinel::keys()->ring()->current()->keyId)->toBe('test-default')
        ->and(Sentinel::keys()->ring('http')->all())->toHaveCount(2)
        ->and(Sentinel::keys()->ring('http')->rotate()->previous?->keyId)->toBe('acme-2026-10')
        ->and(Sentinel::keys()->ring('http')->revoke('acme-2026-10', reason: 'Partner offboarded')->status)->toBe(KeyStatus::Revoked)
        ->and(Sentinel::keys()->ring('http')->retire('acme-2025-10')->status)->toBe(KeyStatus::Retired)
        ->and(count(Sentinel::keys()->all()))->toBe(4);
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

// ── drift checks: everything the README names exists ────────────────────────────

it('names only facade methods that exist', function (): void {
    preg_match_all('/Sentinel::([a-zA-Z]+)\(/', readme(), $matches);
    $names = array_values(array_unique($matches[1]));

    expect($names)->not->toBeEmpty()
        ->and($names)->toContain('importKey', 'check', 'sealables', 'verifiedSignature', 'signatureOwner', 'model', 'fake');

    foreach ($names as $name) {
        expect(method_exists(SentinelManager::class, $name) || method_exists(SentinelFake::class, $name) || method_exists(SentinelFacade::class, $name))->toBeTrue("Sentinel::{$name}() is not a method");
    }
});

it('imports only classes that exist', function (): void {
    preg_match_all('/^use (RoundlyConsulting\\\\Sentinel\\\\[A-Za-z\\\\]+);$/m', readme(), $matches);

    expect($matches[1])->not->toBeEmpty();

    foreach (array_unique($matches[1]) as $class) {
        expect(class_exists($class) || interface_exists($class) || trait_exists($class) || enum_exists($class))->toBeTrue("{$class} does not exist");
    }
});

it('documents only commands and options that exist', function (): void {
    preg_match_all('/^\| `(sentinel:[a-z:-]+)((?: \{[^}]+\})*)` \|/m', readme(), $rows, PREG_SET_ORDER);
    $commands = Artisan::all();

    expect($rows)->toHaveCount(14);

    foreach ($rows as [, $name, $arguments]) {
        expect($commands)->toHaveKey($name);
        $definition = $commands[$name]->getDefinition();
        preg_match_all('/\{(--)?([a-z-]+)/', $arguments, $parts, PREG_SET_ORDER);

        foreach ($parts as [, $dashes, $part]) {
            expect($dashes === '--' ? $definition->hasOption($part) : $definition->hasArgument($part))->toBeTrue("{$name} has no {$dashes}{$part}");
        }
    }
});

it('documents every configuration key, and only those', function (): void {
    $section = explode('## Declaring seals', explode('## Configuration', readme())[1])[0];
    preg_match_all('/^\| `([a-z_.<>]+)`(?: \/ `([a-z_]+)`)?(?: \/ `([a-z_]+)`)*[^|]*\|/m', $section, $rows, PREG_SET_ORDER);
    $documented = [];

    foreach ($rows as $row) {
        $key = str_replace('<name>', 'default', $row[1]);

        if (! str_contains($key, '.') && ! in_array($key, ['context', 'key_type', 'actor_key_type', 'models'], true)) {
            continue;
        }

        $documented[] = $key;
    }

    expect($documented)->not->toBeEmpty();

    foreach ($documented as $key) {
        expect(array_key_exists(explode('.', $key)[0], config('sentinel')) && config()->has("sentinel.{$key}"))->toBeTrue("sentinel.{$key} is not a configuration key");
    }

    foreach (['context', 'key_type', 'actor_key_type', 'models', 'database.connection', 'keys.revoked', 'sealing.transaction_attempts', 'ledger.connections', 'idempotency.replayed_headers', 'nonces.length', 'problems.type_base', 'signatures.advertise', 'signatures.outbound.include_alg', 'schedule.enabled', 'schedule.checkpoint', 'schedule.verify', 'schedule.prune'] as $key) {
        expect($documented)->toContain($key);
    }
});

it('names only environment variables the configuration reads', function (): void {
    preg_match_all('/\bSENTINEL_[A-Z_]+/', readme(), $matches);
    $config = (string) file_get_contents(__DIR__.'/../../config/sentinel.php');

    expect($matches[0])->not->toBeEmpty();

    foreach (array_unique($matches[0]) as $variable) {
        expect($config)->toContain("'{$variable}'");
    }
});

it('names only registered middleware aliases, events and fake assertions', function (): void {
    preg_match_all('/`(sentinel\.(?:verified|idempotent|signed|single-use))/', readme(), $aliases);
    preg_match_all('/^\| `([A-Z][A-Za-z]+)`(?:, `([A-Z][A-Za-z]+)`)*(?:, `([A-Z][A-Za-z]+)`)?(?:, `([A-Z][A-Za-z]+)`)? \| (?:sync|after commit)/m', readme(), $events, PREG_SET_ORDER);
    preg_match_all('/`(assert[A-Za-z]+)`/', readme(), $assertions);
    $registered = app('router')->getMiddleware();

    expect(array_unique($aliases[1]))->toHaveCount(4)
        ->and($events)->not->toBeEmpty()
        ->and(array_unique($assertions[1]))->toHaveCount(36);

    foreach (array_unique($aliases[1]) as $alias) {
        expect($registered)->toHaveKey($alias);
    }

    foreach ($events as $row) {
        foreach (array_filter(array_slice($row, 1)) as $event) {
            expect(class_exists('RoundlyConsulting\\Sentinel\\Events\\'.$event))->toBeTrue("{$event} is not an event");
        }
    }

    foreach (array_unique($assertions[1]) as $assertion) {
        expect(method_exists(SentinelFake::class, $assertion))->toBeTrue("{$assertion} is not a fake assertion");
    }
});
