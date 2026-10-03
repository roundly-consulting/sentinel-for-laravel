<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use RoundlyConsulting\Crypto\Asn1\DerDecoder;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Messages\PsrResponseView;
use RoundlyConsulting\Sentinel\Http\Messages\SymfonyRequestView;
use RoundlyConsulting\Sentinel\Http\Signatures\SignatureBase;
use RoundlyConsulting\Sentinel\Http\StructuredFields\InnerList;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parser;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;

/**
 * §10 item 49: RFC 9421 Appendix B — vectors copied from the RFC text into
 * tests/Fixtures/rfc9421 (no errata touch Appendix B as of 2026-10-02).
 *
 * @return array<string, mixed>
 */
function rfc9421(string $file): array
{
    return json_decode((string) file_get_contents(__DIR__."/../../Fixtures/rfc9421/{$file}.json"), true, 32, JSON_THROW_ON_ERROR);
}

/**
 * The RFC's test-request, as Laravel receives it.
 *
 * @param  array<string, string>  $extra
 */
function rfcRequest(array $extra = []): Request
{
    $message = rfc9421('appendix-b2')['messages']['request'];
    [$method, $target] = explode(' ', $message['start']);
    $server = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $target, 'QUERY_STRING' => explode('?', $target, 2)[1] ?? '', 'HTTPS' => 'on'];

    foreach ($message['headers'] as [$name, $value]) {
        $key = strtoupper(str_replace('-', '_', $name));
        $server[in_array($key, ['CONTENT_TYPE', 'CONTENT_LENGTH'], true) ? $key : 'HTTP_'.$key] = $value;
    }

    foreach ($extra as $name => $value) {
        $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
    }

    return new Request([], [], [], [], [], $server, $message['body']);
}

/**
 * The RFC's test-request as the HTTP client sends it.
 */
function rfcPsrRequest(): PsrRequest
{
    $message = rfc9421('appendix-b2')['messages']['request'];
    [$method, $target] = explode(' ', $message['start']);
    $headers = [];

    foreach ($message['headers'] as [$name, $value]) {
        $headers[$name] = $value;
    }

    return new PsrRequest($method, 'https://example.com'.$target, $headers, $message['body']);
}

/**
 * @param  array<string, string>  $extra
 */
function rfcResponse(array $extra = []): PsrResponse
{
    $message = rfc9421('appendix-b2')['messages']['response'];
    $headers = $extra;

    foreach ($message['headers'] as [$name, $value]) {
        $headers[$name] = $value;
    }

    return new PsrResponse(200, $headers, $message['body']);
}

/**
 * The http ring as a config-driver ring holding the RFC's keys.
 *
 * @param  list<string>  $previous  kid|algorithm|base64:material entries
 */
function rfcRing(?string $kid, ?Algorithm $algorithm, ?string $material, array $previous = []): void
{
    config()->set('sentinel.keys.rings.http.driver', 'config');
    config()->set('sentinel.keys.rings.http.key_id', $kid);
    config()->set('sentinel.keys.rings.http.algorithm', ($algorithm ?? Algorithm::HmacSha256)->value);
    config()->set('sentinel.keys.rings.http.key', $material);
    config()->set('sentinel.keys.rings.http.previous', implode(',', $previous));
    config()->set('sentinel.signatures.profiles.rfc', [
        'ring' => 'http', 'components' => [], 'require_query' => false, 'require_content_digest' => false,
        'require_nonce' => false, 'max_age' => 300, 'clock_skew' => 30, 'algorithms' => ['hmac-sha256', 'ed25519', 'ecdsa-p256-sha256', 'ecdsa-p384-sha384'],
        // The RFC's keys sign and verify here — one store plays both sides.
        'accept_signing_keys' => true,
    ]);
    app(KeyStoreManager::class)->flush();
}

function rfcSharedSecret(): string
{
    return 'base64:'.rfc9421('appendix-b1-keys')['keys']['test-shared-secret']['secret'];
}

/**
 * The RFC's Ed25519 PKCS#8 key as the libsodium secret key Sentinel loads: the 32-byte seed
 * read with crypto's DER decoder, expanded by sodium (an independent oracle).
 */
function rfcEd25519Secret(): string
{
    $pem = rfc9421('appendix-b1-keys')['keys']['test-key-ed25519']['private'];
    $der = Base64::decode((string) preg_replace('/-----[A-Z ]+-----|\s/', '', $pem));
    $seed = (new DerDecoder)->decode((new DerDecoder)->decode($der)->children()[2]->octetString())->octetString();

    return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
}

function rfcEd25519Public(): string
{
    $pem = rfc9421('appendix-b1-keys')['keys']['test-key-ed25519']['public'];

    return substr(Base64::decode((string) preg_replace('/-----[A-Z ]+-----|\s/', '', $pem)), -32);
}

function rfcSignature(string $label): array
{
    return rfc9421('appendix-b2')['signatures'][$label];
}

beforeEach(fn () => Carbon::setTestNow(Carbon::createFromTimestampUTC(1618884473)));
afterEach(fn () => Carbon::setTestNow());

it('derives the RFC\'s Ed25519 public key from its private key', function (): void {
    expect(substr(rfcEd25519Secret(), 32))->toBe(rfcEd25519Public());
});

it('rebuilds every RFC signature base byte for byte', function (string $label, string $message): void {
    $vector = rfcSignature($label);
    $input = Parser::dictionary($vector['signature_input'])['sig-'.$label];

    expect($input)->toBeInstanceOf(InnerList::class);

    $view = $message === 'request' ? new SymfonyRequestView(rfcRequest()) : new PsrResponseView(rfcResponse());

    expect(SignatureBase::build($view, $input))->toBe($vector['base']);
})->with([['b21', 'request'], ['b23', 'request'], ['b24', 'response'], ['b25', 'request'], ['b26', 'request']]);

it('signs B.2.5 (hmac-sha256) byte for byte and verifies it', function (): void {
    rfcRing('test-shared-secret', Algorithm::HmacSha256, rfcSharedSecret());
    $vector = rfcSignature('b25');

    $signed = Sentinel::signatures()->sign(rfcPsrRequest(), 'test-shared-secret', new SigningOptions(
        components: ['date', '@authority', 'content-type'], label: 'sig-b25', nonce: false,
    ));

    expect($signed->getHeaderLine('Signature-Input'))->toBe($vector['signature_input'])
        ->and($signed->getHeaderLine('Signature'))->toBe($vector['signature']);

    $verified = Sentinel::signatures()->verify(rfcRequest(['Signature-Input' => $vector['signature_input'], 'Signature' => $vector['signature']]), 'rfc');

    expect($verified->keyId)->toBe('test-shared-secret')
        ->and($verified->algorithm)->toBe(Algorithm::HmacSha256)
        ->and($verified->label)->toBe('sig-b25')
        ->and($verified->components)->toBe(['date', '@authority', 'content-type'])
        ->and($verified->created)->toBe(1618884473);
});

it('signs B.2.6 (ed25519) byte for byte and verifies it', function (): void {
    rfcRing('test-key-ed25519', Algorithm::Ed25519, 'base64:'.base64_encode(rfcEd25519Secret()));
    $vector = rfcSignature('b26');

    $signed = Sentinel::signatures()->sign(rfcPsrRequest(), 'test-key-ed25519', new SigningOptions(
        components: ['date', '@method', '@path', '@authority', 'content-type', 'content-length'], label: 'sig-b26', nonce: false,
    ));

    expect($signed->getHeaderLine('Signature-Input'))->toBe($vector['signature_input'])
        ->and($signed->getHeaderLine('Signature'))->toBe($vector['signature'])
        ->and(Sentinel::signatures()->verify(rfcRequest(['Signature-Input' => $vector['signature_input'], 'Signature' => $vector['signature']]), 'rfc')->algorithm)->toBe(Algorithm::Ed25519);
});

it('verifies the B.2.4 (ecdsa-p256-sha256) response signature', function (): void {
    $public = 'base64:'.base64_encode(rfc9421('appendix-b1-keys')['keys']['test-key-ecc-p256']['public']);
    rfcRing(null, null, null, ["test-key-ecc-p256|ecdsa-p256-sha256|{$public}"]);
    $vector = rfcSignature('b24');

    $verified = Sentinel::signatures()->verifyResponse(rfcResponse(['Signature-Input' => $vector['signature_input'], 'Signature' => $vector['signature']]), 'rfc');

    expect($verified->algorithm)->toBe(Algorithm::EcdsaP256Sha256)
        ->and($verified->components)->toBe(['@status', 'content-type', 'content-digest', 'content-length']);

    // One flipped bit, and it no longer verifies.
    $forged = str_replace('wNmSUAhwb5', 'wNmSUAhwb6', $vector['signature']);

    expect(fn () => Sentinel::signatures()->verifyResponse(rfcResponse(['Signature-Input' => $vector['signature_input'], 'Signature' => $forged]), 'rfc'))
        ->toThrow(HttpSignatureException::class, 'invalid_signature');
});

it('rejects the rsa-pss-sha512 vectors B.2.1–B.2.3 as unsupported', function (string $label, SignatureRejection $reason): void {
    rfcRing('test-shared-secret', Algorithm::HmacSha256, rfcSharedSecret());
    $vector = rfcSignature($label);

    try {
        Sentinel::signatures()->verify(rfcRequest(['Signature-Input' => $vector['signature_input'], 'Signature' => $vector['signature']]), 'rfc');
        $this->fail('An rsa-pss-sha512 signature was accepted.');
    } catch (HttpSignatureException $exception) {
        expect($exception->reason())->toBe($reason);
    }
})->with([
    // No RSA key can exist in a ring: the key id is unknown.
    'B.2.1' => ['b21', SignatureRejection::UnknownKey],
    // `@query-param;name=` is a component parameter this profile refuses.
    'B.2.2' => ['b22', SignatureRejection::UnsupportedComponent],
    'B.2.3' => ['b23', SignatureRejection::UnknownKey],
]);

it('refuses rsa-pss-sha512 as an algorithm name and as key material', function (): void {
    rfcRing('test-shared-secret', Algorithm::HmacSha256, rfcSharedSecret());
    $input = 'sig1=("@authority");created=1618884473;keyid="test-shared-secret";alg="rsa-pss-sha512"';

    expect(fn () => Sentinel::signatures()->verify(rfcRequest(['Signature-Input' => $input, 'Signature' => 'sig1=:AAAA:']), 'rfc'))
        ->toThrow(HttpSignatureException::class, 'unsupported_algorithm');

    $rsa = 'base64:'.base64_encode(rfc9421('appendix-b1-keys')['keys']['test-key-rsa-pss']['public']);
    config()->set('sentinel.keys.rings.http.previous', "test-key-rsa-pss|rsa-pss-sha512|{$rsa}");
    app(KeyStoreManager::class)->flush();

    expect(fn () => Sentinel::keys()->ring('http')->all())->toThrow(InvalidSentinelConfigurationException::class);
});
