<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Http\Client\Request as ClientRequest;
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
