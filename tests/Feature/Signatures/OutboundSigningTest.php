<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\PumpStream;
use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\ExpectationFailedException;
use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parser;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;

/**
 * Capture what the HTTP client sends.
 */
function sentRequest(Closure $send): RequestInterface
{
    $captured = null;
    Http::fake(static function (ClientRequest $request) use (&$captured) {
        $captured = $request->toPsrRequest();

        return Http::response('ok');
    });

    $send();

    return $captured ?? throw new RuntimeException('nothing was sent');
}

/**
 * §10 item 52: Http::withSignature() — verified by Sentinel's own verifier, per algorithm.
 */
it('signs outgoing requests that its own verifier accepts', function (Algorithm $algorithm): void {
    Sentinel::keys()->ring('http')->generate($algorithm, 'outbound-'.$algorithm->value);
    // Our own verifier stands in for the partner's: it must accept a key this application signs with.
    config()->set('sentinel.signatures.profiles.default.accept_signing_keys', true);

    $sent = sentRequest(static fn () => Http::withSignature('outbound-'.$algorithm->value)->withBody('{"id":1}')->post('https://partner.example/events?x=1'));

    expect($sent->getHeaderLine('Content-Digest'))->toStartWith('sha-256=:')
        ->and(Parser::dictionary($sent->getHeaderLine('Signature-Input')))->toHaveKey('sig1')
        ->and(Sentinel::signatures()->verify(received($sent))->algorithm)->toBe($algorithm);
})->with([Algorithm::HmacSha256, Algorithm::Ed25519, Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384]);

it('leaves out what the request does not carry and keeps other signatures', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'outbound');

    $sent = sentRequest(static fn () => Http::withHeaders(['Signature-Input' => 'sig0=();created=1;keyid="other"', 'Signature' => 'sig0=:AAAA:'])
        ->withSignature('outbound', new SigningOptions(expiresIn: 60, tag: 'app', includeAlg: true, digest: DigestAlgorithm::Sha512))
        ->get('https://partner.example/status'));

    $inputs = Parser::dictionary($sent->getHeaderLine('Signature-Input'));
    $components = array_map(static fn ($item) => $item->value, $inputs['sig1']->items);

    expect(array_keys($inputs))->toBe(['sig0', 'sig1'])
        ->and(array_keys(Parser::dictionary($sent->getHeaderLine('Signature'))))->toBe(['sig0', 'sig1'])
        ->and($components)->toBe(['@method', '@authority', '@path'])
        ->and($sent->hasHeader('Content-Digest'))->toBeFalse()
        ->and($inputs['sig1']->parameters->get('alg'))->toBe('hmac-sha256')
        ->and($inputs['sig1']->parameters->get('tag'))->toBe('app')
        ->and($inputs['sig1']->parameters->get('expires') - $inputs['sig1']->parameters->get('created'))->toBe(60);

    $posted = sentRequest(static fn () => Http::withSignature('outbound', new SigningOptions(digest: DigestAlgorithm::Sha512))->post('https://partner.example/e', ['a' => 1]));

    expect($posted->getHeaderLine('Content-Digest'))->toStartWith('sha-512=:');
});

it('signs only with an active key of the outbound ring', function (): void {
    expect(fn () => Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'missing'))->toThrow(UnknownKeyException::class);

    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'retiring');
    Sentinel::keys()->ring('http')->revoke('retiring', 'leaked');

    expect(fn () => Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'retiring'))->toThrow(NoSigningKeyException::class);

    config()->set('sentinel.keys.rings.http.algorithms', ['hmac-sha256', 'hmac-sha512']);
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha512, 'wide');

    expect(fn () => Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'wide'))->toThrow(AlgorithmNotAllowedException::class);
});

it('records outgoing signatures under the fake', function (): void {
    $fake = Sentinel::fake();

    $sent = sentRequest(static fn () => Http::withSignature('partner-key')->get('https://partner.example/'));

    expect($sent->hasHeader('Signature'))->toBeFalse();

    $fake->assertRequestSigned();
    $fake->assertRequestSigned('partner-key');

    expect(fn () => $fake->assertRequestSigned('other'))->toThrow(ExpectationFailedException::class, '[other]');
});

it('signs the request as it is finally sent, after every later middleware and callback (dual-review O-21)', function (Closure $later): void {
    partnerRing();
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000));

    $sent = sentRequest(static fn () => $later(Http::withSignature('partner'))->post('https://api.example.com/events', ['a' => 1]));

    expect($sent->getHeaderLine('Content-Type'))->toBe('application/vnd.api+json')
        ->and(Sentinel::signatures()->verify(received($sent))->keyId)->toBe('partner');

    Carbon::setTestNow();
})->with([
    'a later request middleware' => [static fn (PendingRequest $request): PendingRequest => $request->withRequestMiddleware(
        static fn (RequestInterface $psr): RequestInterface => $psr->withHeader('Content-Type', 'application/vnd.api+json'),
    )],
    'a later beforeSending callback' => [static fn (PendingRequest $request): PendingRequest => $request->beforeSending(
        static fn (ClientRequest $client): RequestInterface => $client->toPsrRequest()->withHeader('Content-Type', 'application/vnd.api+json'),
    )],
]);

it('never drains a non-seekable body it signs (dual-review O-22)', function (array $components, bool $digested): void {
    partnerRing();
    $chunks = ['{"a":', '1}'];
    $body = new PumpStream(static function () use (&$chunks): string|false {
        return array_shift($chunks) ?? false;
    });

    $signed = Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/e', ['Content-Type' => 'application/json'], $body), 'partner', new SigningOptions(components: $components));

    expect((string) $signed->getBody())->toBe('{"a":1}')
        ->and($signed->hasHeader('Content-Digest'))->toBe($digested);

    if ($digested) {
        expect(Sentinel::signatures()->verify(received($signed))->keyId)->toBe('partner');
    }
})->with([
    'content-digest not covered (the body is not read)' => [['@method', '@authority', '@path'], false],
    'content-digest covered (the body is buffered)' => [['@method', '@authority', '@path', 'content-digest'], true],
]);
