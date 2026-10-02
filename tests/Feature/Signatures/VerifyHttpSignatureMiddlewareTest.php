<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Idempotency\RequestScope;

/**
 * Send a PSR-7 request through the application's kernel as received.
 */
function dispatchReceived(Request $request): TestResponse
{
    return test()->createTestResponse(app(Kernel::class)->handle($request), $request);
}

beforeEach(function (): void {
    partnerRing();
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000));
    config()->set('app.debug', false);

    Route::post('/events', static fn (Request $request): array => [
        'key' => $request->attributes->get('sentinel.signature')?->keyId,
        'scope' => app(RequestScope::class)->resolve($request),
    ])->middleware('sentinel.signed');
});

afterEach(fn () => Carbon::setTestNow());

it('lets a signed request through with the verified signature attached', function (): void {
    $response = dispatchReceived(received(signedPartnerRequest(uri: 'https://api.example.com/events')));

    $response->assertOk()->assertJson(['key' => 'partner', 'scope' => 'sig:http:partner']);
});

/**
 * §10 item 54: the 401 problem response.
 */
it('answers 401 problem details with a generic code and an Accept-Signature hint', function (): void {
    $response = dispatchReceived(received(new PsrRequest('POST', 'https://api.example.com/events?page=2', ['Content-Type' => 'application/json'], '{"a":1}')));

    $response->assertUnauthorized()
        ->assertHeader('Content-Type', 'application/problem+json')
        ->assertJson(['status' => 401, 'code' => 'signature_rejected', 'title' => 'Signature rejected'])
        ->assertHeader('Accept-Signature', 'sig1=("@method" "@authority" "@path" "@query" "content-digest");created;nonce');

    config()->set('app.debug', true);
    config()->set('sentinel.signatures.profiles.default.tag', 'partner-api');
    config()->set('sentinel.signatures.profiles.default.require_nonce', false);

    dispatchReceived(received(new PsrRequest('POST', 'https://api.example.com/events')))
        ->assertUnauthorized()
        ->assertJson(['code' => 'missing_signature'])
        ->assertHeader('Accept-Signature', 'sig1=("@method" "@authority" "@path");created;tag="partner-api"');

    config()->set('sentinel.signatures.advertise', 'off');

    dispatchReceived(received(new PsrRequest('POST', 'https://api.example.com/events')))->assertHeaderMissing('Accept-Signature');
});

it('is driven by the fake in tests', function (): void {
    $fake = Sentinel::fake();

    dispatchReceived(received(new PsrRequest('POST', 'https://api.example.com/events')))->assertOk()->assertJson(['key' => 'fake']);

    $fake->fakeVerifiedSignature(new VerifiedSignature('sig1', 'http', 'acme', Algorithm::Ed25519, 1, null, null, null, ['@method']));
    dispatchReceived(received(new PsrRequest('POST', 'https://api.example.com/events')))->assertJson(['key' => 'acme', 'scope' => 'sig:http:acme']);

    $fake->rejectSignatures(SignatureRejection::Replayed);
    dispatchReceived(received(new PsrRequest('POST', 'https://api.example.com/events')))->assertUnauthorized();

    expect(fn () => Sentinel::signatures()->verifyResponse(new PsrResponse(200)))->toThrow(HttpSignatureException::class)
        ->and(fn () => Sentinel::signatures()->verify(Request::create('/'), 'nope'))->toThrow(InvalidSentinelConfigurationException::class);

    $fake->fakeVerifiedSignature();

    expect(Sentinel::signatures()->verifyResponse(new PsrResponse(200))->keyId)->toBe('fake')
        ->and($fake->recorded('verifyRequestSignature'))->toHaveCount(3)
        ->and(fn () => $fake->assertRequestSigned())->toThrow(ExpectationFailedException::class);
});
