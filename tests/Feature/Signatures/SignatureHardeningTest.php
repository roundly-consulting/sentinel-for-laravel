<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;

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
