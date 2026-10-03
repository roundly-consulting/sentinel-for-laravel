<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;

/**
 * RFC 9421 defects the dual review found: what a signature covers must be what the
 * application executes, for as long as the signature is accepted.
 */
function dispatchSigned(Request $request): TestResponse
{
    return test()->createTestResponse(app(Kernel::class)->handle($request), $request);
}

function rejectionOf(Request $request): ?SignatureRejection
{
    try {
        Sentinel::signatures()->verify($request);

        return null;
    } catch (HttpSignatureException $exception) {
        return $exception->reason();
    }
}

beforeEach(function (): void {
    partnerRing();
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000));
    config()->set('app.debug', true);
});

afterEach(fn () => Carbon::setTestNow());

it('never executes a signed request under an overridden method (dual-review O-8)', function (array $server, array $query): void {
    Request::enableHttpMethodParameterOverride();
    Route::post('/orders/1', static fn (): array => ['action' => 'update'])->middleware('sentinel.signed');
    Route::delete('/orders/1', static fn (): array => ['action' => 'DELETE'])->middleware('sentinel.signed');

    $sign = static fn (): PsrRequest => Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/orders/1', ['Content-Type' => 'application/json'], '{"note":"x"}'), 'partner');

    dispatchSigned(received($sign()))->assertOk()->assertJson(['action' => 'update']);

    $tampered = received($sign(), $server);
    $tampered->query->add($query);

    expect(dispatchSigned($tampered)->status())->toBe(401)
        ->and(rejectionOf(received($sign(), $server)))->toBe($server === [] ? null : SignatureRejection::Malformed);
})->with([
    'X-HTTP-Method-Override' => [['HTTP_X_HTTP_METHOD_OVERRIDE' => 'DELETE'], []],
    '_method' => [[], ['_method' => 'DELETE']],
]);

it('requires a digest for a multipart body PHP never handed over raw (dual-review O-9)', function (): void {
    Route::post('/payouts', static fn (Request $request): array => $request->all())->middleware('sentinel.signed');

    // Signed without a body — then delivered as multipart/form-data with attacker fields.
    $signed = Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/payouts'), 'partner');
    $server = received($signed, ['CONTENT_TYPE' => 'multipart/form-data; boundary=x', 'CONTENT_LENGTH' => '120'])->server->all();
    $request = new Request([], ['iban' => 'ATTACKER', 'amount' => '1000000'], [], [], [], $server, '');

    expect(dispatchSigned($request)->status())->toBe(401)
        ->and(dispatchSigned(new Request([], ['iban' => 'ATTACKER'], [], [], [], $server, ''))->headers->get('Accept-Signature'))->toContain('"content-digest"')
        ->and(rejectionOf(new Request([], ['iban' => 'ATTACKER'], [], [], [], $server, '')))->toBe(SignatureRejection::MissingComponent);

    // A GET with a query is not a body: Laravel's input bag holds the query there.
    $get = Sentinel::signatures()->sign(new PsrRequest('GET', 'https://api.example.com/payouts?page=2'), 'partner');

    expect(rejectionOf(received($get)))->toBeNull();
});

it('verifies a digest-covered multipart body only when PHP hands over the raw bytes (dual-review O-9)', function (): void {
    Route::post('/upload', static fn (Request $request): array => ['ok' => true])->middleware('sentinel.signed');
    $body = "--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--x--\r\n";
    $sign = static fn (): PsrRequest => Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/upload', ['Content-Type' => 'multipart/form-data; boundary=x'], $body), 'partner');

    // enable_post_data_reading = On: the raw bytes are gone, the digest cannot be checked.
    $parsed = new Request([], ['a' => '1'], [], [], [], received($sign())->server->all(), '');

    expect(rejectionOf($parsed))->toBe(SignatureRejection::DigestMismatch);

    // enable_post_data_reading = Off: php://input keeps the body, and it verifies.
    dispatchSigned(received($sign()))->assertOk();
});

it('remembers a nonce for the whole last second of the window (dual-review O-10)', function (string $store): void {
    if ($store === 'cache') {
        config()->set('sentinel.nonces.store', 'cache');
        config()->set('sentinel.nonces.cache_store', 'array');
        app()->forgetInstance(NonceStore::class);
    }

    $signed = Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/events', ['Content-Type' => 'application/json'], '{"a":1}'), 'partner');

    expect(rejectionOf(received($signed)))->toBeNull()
        ->and(rejectionOf(received($signed)))->toBe(SignatureRejection::Replayed);

    // 330.4 s later (max_age 300 + skew 30): the window still accepts it — the nonce must hold.
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000)->addMicroseconds(330_400_000));

    expect(rejectionOf(received($signed)))->toBe(SignatureRejection::Replayed);

    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_331));

    expect(rejectionOf(received($signed)))->toBe(SignatureRejection::TooOld);
})->with(['database', 'cache']);

it('enforces the ring\'s algorithm allow-list when signing and verifying (dual-review O-19)', function (): void {
    config()->set('sentinel.keys.rings.http.driver', 'database');
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring('http')->import('legacy-hmac', Algorithm::HmacSha256, PARTNER_SECRET, signing: true);
    $signed = Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/events', ['Content-Type' => 'application/json'], '{"a":1}'), 'legacy-hmac');

    // The operator retires shared secrets for the http ring.
    config()->set('sentinel.keys.rings.http.algorithms', ['ed25519']);
    app(KeyStoreManager::class)->flush();

    expect(fn () => Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/events'), 'legacy-hmac'))->toThrow(AlgorithmNotAllowedException::class)
        ->and(rejectionOf(received($signed)))->toBe(SignatureRejection::AlgorithmNotAllowed);
});
