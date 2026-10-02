<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use GuzzleHttp\Psr7\Response as PsrResponse;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Events\HttpSignatureRejected;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Messages\PsrResponseView;
use RoundlyConsulting\Sentinel\Http\Messages\SymfonyRequestView;
use RoundlyConsulting\Sentinel\Http\Signatures\ComponentResolver;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\Key;

function rejection(Request $request, ?string $profile = null): ?SignatureRejection
{
    try {
        Sentinel::signatures()->verify($request, $profile);

        return null;
    } catch (HttpSignatureException $exception) {
        return $exception->reason();
    }
}

function withHeader(RequestInterface $request, string $name, string $value): Request
{
    return received($request->withHeader($name, $value));
}

beforeEach(function (): void {
    partnerRing();
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000));
});

afterEach(fn () => Carbon::setTestNow());

/**
 * §10 item 51: every rejection is reachable, and the one valid path is not rejected.
 */
it('accepts a well-formed signature and exposes it', function (): void {
    $verified = Sentinel::signatures()->verify(received(signedPartnerRequest()));

    expect($verified->keyId)->toBe('partner')
        ->and($verified->ring)->toBe('http')
        ->and($verified->components)->toBe(['@method', '@authority', '@path', '@query', 'content-digest', 'content-type'])
        ->and($verified->nonce)->toHaveLength(32)
        ->and($verified->created)->toBe(1_800_000_000);
});

it('rejects with the precise reason', function (Closure $request, SignatureRejection $reason): void {
    Event::fake([HttpSignatureRejected::class]);

    expect(rejection($request()))->toBe($reason);

    Event::assertDispatched(HttpSignatureRejected::class, static fn (HttpSignatureRejected $event): bool => $event->reason === $reason && $event->method === 'POST');
})->with([
    'no signature' => [fn () => received(new PsrRequest('POST', 'https://api.example.com/events')), SignatureRejection::Missing],
    'an unparsable input' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=(('), SignatureRejection::Malformed],
    'a signature that is not bytes' => [fn () => withHeader(signedPartnerRequest(), 'Signature', 'sig1="abc"'), SignatureRejection::Malformed],
    'a label without a signature' => [fn () => withHeader(signedPartnerRequest(), 'Signature', 'sig2=:AAAA:'), SignatureRejection::Missing],
    'two labels' => [fn () => received(signedPartnerRequest(new SigningOptions(label: 'sig2'), headers: ['Content-Type' => 'application/json', 'Signature-Input' => 'sig1=();created=1;keyid="x"', 'Signature' => 'sig1=:AAAA:'])), SignatureRejection::Ambiguous],
    'no keyid' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("@method");created=1800000000;nonce="n"'), SignatureRejection::MissingParameter],
    'no created' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("@method");keyid="partner";nonce="n"'), SignatureRejection::MissingParameter],
    'no nonce' => [fn () => received(signedPartnerRequest(new SigningOptions(nonce: false))), SignatureRejection::MissingParameter],
    'created as a string' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("@method");created="1800000000";keyid="partner";nonce="n"'), SignatureRejection::Malformed],
    'an over-long nonce' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("@method");created=1800000000;keyid="partner";nonce="'.str_repeat('n', 257).'"'), SignatureRejection::Malformed],
    'a duplicate component' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("@method" "@method");created=1800000000;keyid="partner";nonce="n"'), SignatureRejection::Malformed],
    'an uppercase component' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("Content-Type");created=1800000000;keyid="partner";nonce="n"'), SignatureRejection::Malformed],
    'a component parameter' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("content-type";sf);created=1800000000;keyid="partner";nonce="n"'), SignatureRejection::UnsupportedComponent],
    '@request-target' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("@request-target");created=1800000000;keyid="partner";nonce="n"'), SignatureRejection::UnsupportedComponent],
    'an unknown derived component' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', 'sig1=("@everything");created=1800000000;keyid="partner";nonce="n"'), SignatureRejection::UnsupportedComponent],
    'a required component not covered' => [fn () => received(signedPartnerRequest(new SigningOptions(components: ['@authority', '@path', '@query', 'content-digest']))), SignatureRejection::MissingComponent],
    'the query not covered' => [fn () => received(signedPartnerRequest(new SigningOptions(components: ['@method', '@authority', '@path', 'content-digest']))), SignatureRejection::MissingComponent],
    'the body not covered' => [fn () => received(signedPartnerRequest(new SigningOptions(components: ['@method', '@authority', '@path', '@query']))), SignatureRejection::MissingComponent],
    'a covered header that is gone' => [fn () => received(signedPartnerRequest(new SigningOptions(components: ['@method', '@authority', '@path', '@query', 'content-digest', 'x-trace']), headers: ['X-Trace' => 't'])->withoutHeader('X-Trace')), SignatureRejection::MissingComponent],
    'an unknown key' => [fn () => withHeader(signedPartnerRequest(), 'Signature-Input', str_replace('keyid="partner"', 'keyid="stranger"', signedPartnerRequest()->getHeaderLine('Signature-Input'))), SignatureRejection::UnknownKey],
    'an unsupported alg' => [fn () => received(signedPartnerRequest()->withHeader('Signature-Input', str_replace(';keyid=', ';alg="rsa-pss-sha512";keyid=', signedPartnerRequest()->getHeaderLine('Signature-Input')))), SignatureRejection::UnsupportedAlgorithm],
    'another alg' => [fn () => received(signedPartnerRequest(new SigningOptions(includeAlg: true))->withHeader('Signature-Input', str_replace('alg="hmac-sha256"', 'alg="ed25519"', signedPartnerRequest(new SigningOptions(includeAlg: true))->getHeaderLine('Signature-Input')))), SignatureRejection::AlgorithmMismatch],
    'a tampered body' => [fn () => received(signedPartnerRequest()->withBody(Utils::streamFor('{"event":"refunded"}'))), SignatureRejection::DigestMismatch],
    'a deprecated digest only' => [fn () => received(signedPartnerRequest(new SigningOptions(components: ['@method', '@authority', '@path', '@query', 'content-digest']))->withHeader('Content-Digest', 'md5=:Sd/dVLAcvNLSq16eXua5uQ==:')), SignatureRejection::UnsupportedDigest],
    'a tampered covered header' => [fn () => withHeader(signedPartnerRequest(), 'Content-Type', 'text/plain'), SignatureRejection::InvalidSignature],
    'a re-sorted query' => [fn () => received(signedPartnerRequest(), ['QUERY_STRING' => 'a=1&b=2', 'REQUEST_URI' => '/events?a=1&b=2']), SignatureRejection::InvalidSignature],
]);

it('reaches the profile-dependent rejections', function (): void {
    config()->set('sentinel.signatures.profiles.default.algorithms', ['ed25519']);
    expect(rejection(received(signedPartnerRequest())))->toBe(SignatureRejection::AlgorithmNotAllowed);

    config()->set('sentinel.signatures.profiles.default.algorithms', ['hmac-sha256']);
    config()->set('sentinel.signatures.profiles.default.tag', 'app');
    expect(rejection(received(signedPartnerRequest(new SigningOptions(tag: 'other')))))->toBe(SignatureRejection::TagMismatch)
        ->and(rejection(received(signedPartnerRequest(new SigningOptions(tag: 'app')))))->toBeNull();

    // Two labels, one carrying the profile's tag: that one is chosen.
    $tagged = signedPartnerRequest(new SigningOptions(label: 'sig2', tag: 'app'), headers: ['Content-Type' => 'application/json', 'Signature-Input' => 'sig1=();created=1;keyid="x"', 'Signature' => 'sig1=:AAAA:']);
    expect(rejection(received($tagged)))->toBeNull()
        ->and(rejection(received($tagged->withHeader('Signature-Input', str_replace('tag="app"', 'tag="nope"', $tagged->getHeaderLine('Signature-Input'))))))->toBe(SignatureRejection::Ambiguous);

    config()->set('sentinel.signatures.profiles.default.tag', null);
    config()->set('sentinel.signatures.profiles.default.label', 'sig1');
    // The configured label wins: sig1 (no nonce) is checked, not the valid sig2.
    expect(rejection(received($tagged)))->toBe(SignatureRejection::MissingParameter);

    config()->set('sentinel.signatures.profiles.default.label', null);
    $signed = signedPartnerRequest();
    config()->set('sentinel.keys.revoked', 'http:partner');
    app(KeyStoreManager::class)->flush();
    expect(rejection(received($signed)))->toBe(SignatureRejection::RevokedKey);
});

it('refuses retired and pending database keys as unknown', function (): void {
    config()->set('sentinel.keys.rings.http.driver', 'database');
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'partner');
    $signed = signedPartnerRequest();
    Sentinel::keys()->ring('http')->retire('partner');

    expect(rejection(received($signed)))->toBe(SignatureRejection::UnknownKey);

    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'future', activatesAt: now()->addDay());
    $early = $signed->withHeader('Signature-Input', str_replace('keyid="partner"', 'keyid="future"', $signed->getHeaderLine('Signature-Input')));

    // A key that is not active yet verifies nothing; an edited key row is an integrity failure.
    expect(rejection(received($early)))->toBe(SignatureRejection::UnknownKey);

    Key::query()->where('kid', 'future')->update(['algorithm' => 'ed25519']);
    app(KeyStoreManager::class)->flush();

    expect(rejection(received($early)))->toBe(SignatureRejection::UnknownKey);
});

it('enforces the time window with inclusive boundaries', function (int $created, ?int $expires, ?SignatureRejection $expected): void {
    $now = 1_800_000_000;
    $input = 'sig1=("@method" "@authority" "@path" "@query" "content-digest" "content-type");created='.($now + $created).($expires === null ? '' : ';expires='.($now + $expires)).';keyid="partner";nonce="'.bin2hex(random_bytes(8)).'"';
    $request = signedPartnerRequest()->withHeader('Signature-Input', $input);
    $rejection = rejection(received($request));

    // Only the window decides here: past it, the (now stale) MAC is what fails.
    expect($rejection === SignatureRejection::InvalidSignature ? null : $rejection)->toBe($expected);
})->with([
    'created at the skew edge' => [30, null, null],
    'created past the skew' => [31, null, SignatureRejection::NotYetValid],
    'created at the max-age edge' => [-330, null, null],
    'created past max age' => [-331, null, SignatureRejection::TooOld],
    'expires at the skew edge' => [0, -30, null],
    'expired' => [0, -31, SignatureRejection::Expired],
]);

it('counts a nonce only after the signature verified', function (): void {
    $signed = signedPartnerRequest();

    expect(rejection(withHeader($signed, 'Content-Type', 'text/plain')))->toBe(SignatureRejection::InvalidSignature)
        ->and(rejection(received($signed)))->toBeNull()
        ->and(rejection(received($signed)))->toBe(SignatureRejection::Replayed);

    // Outside the window the nonce may come back.
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000 + 331));
    expect(rejection(received($signed)))->toBe(SignatureRejection::TooOld);
});

it('derives @authority, @scheme and @target-uri as received, proxies included', function (): void {
    $default = received(signedPartnerRequest(new SigningOptions(components: ['@method', '@authority', '@scheme', '@target-uri', '@path', '@query', 'content-digest']), 'https://API.example.com:443/events?b=2&a=1'));
    $port = received(signedPartnerRequest(new SigningOptions(components: ['@method', '@authority', '@scheme', '@target-uri', '@path', '@query', 'content-digest']), 'https://api.example.com:8443/events?b=2&a=1'));

    expect(rejection($default))->toBeNull()
        ->and(rejection($port))->toBeNull();

    // Behind a trusted proxy, the client's view (X-Forwarded-*) is what was signed.
    $client = signedPartnerRequest(new SigningOptions(components: ['@method', '@authority', '@scheme', '@path', '@query', 'content-digest']), 'https://public.example.com/events?b=2&a=1');
    $proxied = received($client, ['HTTP_HOST' => 'internal:8080', 'HTTPS' => 'off', 'SERVER_PORT' => 8080, 'REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_HOST' => 'public.example.com', 'HTTP_X_FORWARDED_PROTO' => 'https', 'HTTP_X_FORWARDED_PORT' => '443']);

    expect(rejection($proxied))->toBe(SignatureRejection::InvalidSignature);

    Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_HOST | Request::HEADER_X_FORWARDED_PORT | Request::HEADER_X_FORWARDED_PROTO);

    try {
        expect(rejection($proxied))->toBeNull();
    } finally {
        Request::setTrustedProxies([], -1);
    }
});

it('refuses an unknown or invalid profile', function (): void {
    expect(fn () => Sentinel::signatures()->verify(received(signedPartnerRequest()), 'nope'))->toThrow(InvalidSentinelConfigurationException::class, 'nope');

    config()->set('sentinel.signatures.profiles.default.components', ['@query-param']);
    expect(fn () => Sentinel::signatures()->verify(received(signedPartnerRequest())))->toThrow(InvalidSentinelConfigurationException::class);

    config()->set('sentinel.signatures.profiles.default.components', ['@method']);
    config()->set('sentinel.signatures.profiles.default.algorithms', ['hmac-sha512']);
    expect(fn () => Sentinel::signatures()->verify(received(signedPartnerRequest())))->toThrow(InvalidSentinelConfigurationException::class);

    config()->set('sentinel.signatures.profiles.default.algorithms', ['hmac-sha256']);
    config()->set('sentinel.signatures.profiles.default.max_age', 'forever');
    expect(fn () => Sentinel::signatures()->verify(received(signedPartnerRequest())))->toThrow(InvalidSentinelConfigurationException::class, 'max_age');
});

it('validates every profile setting', function (string $key, mixed $value): void {
    $request = received(signedPartnerRequest());
    config()->set("sentinel.signatures.profiles.default.{$key}", $value);

    expect(fn () => Sentinel::signatures()->verify($request))->toThrow(InvalidSentinelConfigurationException::class, $key);
})->with([
    ['ring', 'nowhere'],
    ['label', 'Not A Label'],
    ['tag', "tab\t"],
    ['components', '@method'],
    ['algorithms', []],
    ['clock_skew', 7200],
]);

it('reads header components strictly and derives nothing a message lacks', function (): void {
    $response = new PsrResponseView(new PsrResponse(204, ['X-A' => ['1', '2']]));

    expect([$response->method(), $response->scheme(), $response->authority(), $response->path(), $response->query(), $response->isRequest()])->toBe([null, null, null, null, null, false])
        ->and(ComponentResolver::value($response, 'x-a'))->toBe('1, 2')
        ->and(ComponentResolver::value($response, '@status'))->toBe('204')
        ->and(fn () => ComponentResolver::value($response, '@method'))->toThrow(HttpSignatureException::class, 'unsupported_component')
        ->and(fn () => ComponentResolver::value($response, 'bad header'))->toThrow(HttpSignatureException::class, 'malformed')
        ->and(fn () => ComponentResolver::value(new SymfonyRequestView(Request::create('/')), '@status'))->toThrow(HttpSignatureException::class, 'unsupported_component');
});

it('verifies partners listed as verify-only config keys in a chained ring', function (): void {
    partnerRing();
    $request = received(signedPartnerRequest());

    // The partner's secret only as a verify-only entry; database keys stay reachable.
    config()->set('sentinel.keys.rings.http.driver', 'chain');
    config()->set('sentinel.keys.rings.http.key_id', null);
    config()->set('sentinel.keys.rings.http.key', null);
    config()->set('sentinel.keys.rings.http.previous', 'partner|hmac-sha256|'.PARTNER_SECRET);
    app(KeyStoreManager::class)->flush();

    expect(rejection($request))->toBeNull()
        ->and(Sentinel::keys()->ring('http')->find('partner')?->status)->toBe(KeyStatus::VerifyOnly)
        ->and(fn () => Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'partner'))->toThrow(NoSigningKeyException::class);
});
