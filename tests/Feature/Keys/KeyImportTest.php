<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Events\KeyImported;
use RoundlyConsulting\Sentinel\Events\KeyIntegrityViolated;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * I-1: partners are onboarded at runtime — their public key or shared secret is imported into
 * the http ring's database store, bound to the partner model, and stays verify-only.
 */
const ED25519_SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

function pem(string $label, string $der): string
{
    return "-----BEGIN {$label}-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END {$label}-----\n";
}

function rawPem(string $encoded): string
{
    return (string) base64_decode(substr($encoded, 7), true);
}

/**
 * A request signed with the partner's own private material (on the partner's side), then the
 * http ring reset to the database driver only — as on our side of the integration.
 */
function signedByPartner(string $kid, Algorithm $algorithm, KeyMaterial $partner): Request
{
    partnerRing($kid, $algorithm, (string) $partner->encodedPrivate());
    $request = received(Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/events?b=2&a=1', ['Content-Type' => 'application/json'], '{"event":"paid"}'), $kid));

    config()->set('sentinel.keys.rings.http.driver', 'database');
    config()->set('sentinel.keys.rings.http.key_id', null);
    config()->set('sentinel.keys.rings.http.key', null);
    app(KeyStoreManager::class)->flush();

    return $request;
}

it('onboards an Ed25519 partner whose requests pass sentinel.signed with the partner as owner', function (): void {
    Event::fake([KeyImported::class]);
    $partner = User::query()->create(['name' => 'Acme']);
    $material = KeyMaterial::generate(Algorithm::Ed25519);
    $request = signedByPartner('acme-2026-10', Algorithm::Ed25519, $material);

    $info = Sentinel::keys()->ring('http')->import('acme-2026-10', Algorithm::Ed25519, (string) $material->encodedPublic(), owner: $partner, label: 'Acme');

    expect($info->status)->toBe(KeyStatus::VerifyOnly)
        ->and($info->canSign)->toBeFalse()
        ->and($info->driver)->toBe('database')
        ->and($info->ownerType)->toBe($partner->getMorphClass())
        ->and((string) $info->ownerId)->toBe((string) $partner->getKey())
        ->and($info->label)->toBe('Acme');

    Route::post('/events', static fn (Request $received): array => [
        'owner' => $received->attributes->get('sentinel.signature')?->ownerType.':'.$received->attributes->get('sentinel.signature')?->ownerId,
    ])->middleware('sentinel.signed');

    $response = app(Kernel::class)->handle($request);

    expect($response->getStatusCode())->toBe(200)
        ->and(json_decode((string) $response->getContent(), true))->toBe(['owner' => $partner->getMorphClass().':'.$partner->getKey()]);

    Event::assertDispatched(KeyImported::class, static fn (KeyImported $event): bool => $event->ring === 'http' && $event->keyId === 'acme-2026-10'
        && $event->algorithm === Algorithm::Ed25519 && ! $event->signing && $event->actorType === null);
});

it('accepts an Ed25519 public key as SPKI PEM', function (): void {
    $material = KeyMaterial::generate(Algorithm::Ed25519);
    $request = signedByPartner('pem-ed', Algorithm::Ed25519, $material);
    $spki = pem('PUBLIC KEY', ED25519_SPKI_PREFIX.rawPem((string) $material->encodedPublic()));

    Sentinel::keys()->ring('http')->import('pem-ed', Algorithm::Ed25519, $spki);

    expect(Sentinel::signatures()->verify($request)->keyId)->toBe('pem-ed');
});

it('imports ECDSA P-256 keys as raw PEM and as base64: PEM', function (string $form): void {
    $material = KeyMaterial::generate(Algorithm::EcdsaP256Sha256);
    $request = signedByPartner('ec-partner', Algorithm::EcdsaP256Sha256, $material);
    $public = (string) $material->encodedPublic();

    Sentinel::keys()->ring('http')->import('ec-partner', Algorithm::EcdsaP256Sha256, $form === 'pem' ? rawPem($public) : $public);

    expect(Sentinel::signatures()->verify($request)->algorithm)->toBe(Algorithm::EcdsaP256Sha256)
        ->and(Sentinel::keys()->ring('http')->find('ec-partner')?->status)->toBe(KeyStatus::VerifyOnly);
})->with(['pem', 'base64']);

it('refuses a P-384 key under ecdsa-p256-sha256', function (): void {
    $p384 = KeyMaterial::generate(Algorithm::EcdsaP384Sha384);

    expect(fn () => Sentinel::keys()->ring('http')->import('wrong-curve', Algorithm::EcdsaP256Sha256, rawPem((string) $p384->encodedPublic())))
        ->toThrow(InvalidKeyMaterialException::class, 'curve does not match ecdsa-p256-sha256')
        ->and(Key::query()->count())->toBe(0);
});

it('keeps an imported HMAC secret verify-only unless imported for signing', function (): void {
    Sentinel::keys()->ring('http')->import('shared', Algorithm::HmacSha256, PARTNER_SECRET);

    expect(Sentinel::keys()->ring('http')->find('shared')?->status)->toBe(KeyStatus::VerifyOnly)
        ->and(fn () => Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'shared'))->toThrow(NoSigningKeyException::class)
        ->and(fn () => Sentinel::keys()->ring('http')->current())->toThrow(NoSigningKeyException::class);

    $info = Sentinel::keys()->ring('http')->import('ours', Algorithm::HmacSha256, 'base64:'.base64_encode(random_bytes(32)), signing: true);
    $signed = Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'ours');

    expect($info->status)->toBe(KeyStatus::Active)
        ->and($info->canSign)->toBeTrue()
        ->and($signed->getHeaderLine('Signature-Input'))->toContain('keyid="ours"')
        ->and(Sentinel::keys()->ring('http')->current()->keyId)->toBe('ours');
});

it('accepts private asymmetric material only for signing', function (Algorithm $algorithm): void {
    $material = KeyMaterial::generate($algorithm);
    $private = (string) $material->encodedPrivate();

    expect(fn () => Sentinel::keys()->ring('http')->import('own', $algorithm, $private))->toThrow(InvalidKeyMaterialException::class, 'is a private key');

    $info = Sentinel::keys()->ring('http')->import('own', $algorithm, $algorithm === Algorithm::Ed25519 ? $private : rawPem($private), signing: true);

    expect($info->status)->toBe(KeyStatus::Active)
        ->and(Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'own')->getHeaderLine('Signature'))->not->toBe('');
})->with([Algorithm::Ed25519, Algorithm::EcdsaP256Sha256, Algorithm::EcdsaP384Sha384]);

it('keeps a public key verify-only even when imported for signing', function (): void {
    $info = Sentinel::keys()->ring('http')->import('pub', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPublic(), signing: true);

    expect($info->status)->toBe(KeyStatus::VerifyOnly);
});

it('refuses a kid taken in the database or on the config side of a chain ring', function (): void {
    Sentinel::keys()->ring('http')->import('taken', Algorithm::HmacSha256, PARTNER_SECRET);

    expect(fn () => Sentinel::keys()->ring('http')->import('taken', Algorithm::HmacSha256, PARTNER_SECRET))->toThrow(KeyDriverException::class, 'already has a key [taken]');

    partnerRing('config-partner');
    config()->set('sentinel.keys.rings.http.driver', 'chain');
    app(KeyStoreManager::class)->flush();

    expect(fn () => Sentinel::keys()->ring('http')->import('config-partner', Algorithm::HmacSha256, PARTNER_SECRET))->toThrow(KeyDriverException::class, 'already has a key [config-partner]')
        ->and(Key::query()->count())->toBe(1);
});

it('refuses a config-only ring with the environment format of verify-only keys', function (): void {
    partnerRing();

    expect(fn () => Sentinel::keys()->ring('http')->import('p2', Algorithm::HmacSha256, PARTNER_SECRET))
        ->toThrow(KeyDriverException::class, 'list verify-only keys in sentinel.keys.rings.http.previous as kid|algorithm|base64:… (SENTINEL_HTTP_KEYS in the shipped config)')
        ->and(fn () => Sentinel::keys()->ring()->import('d2', Algorithm::HmacSha256, PARTNER_SECRET))
        ->toThrow(KeyDriverException::class, '(SENTINEL_PREVIOUS_KEYS in the shipped config)');
});

it('validates every input before storing anything', function (string $kid, Algorithm $algorithm, string $material, ?string $label, string $exception, string $message): void {
    expect(fn () => Sentinel::keys()->ring('http')->import($kid, $algorithm, $material, label: $label))->toThrow($exception, $message)
        ->and(Key::query()->count())->toBe(0);
})->with([
    'disallowed algorithm' => ['k', Algorithm::HmacSha512, PARTNER_SECRET, null, AlgorithmNotAllowedException::class, 'hmac-sha512'],
    'invalid kid' => ['-bad kid', Algorithm::HmacSha256, PARTNER_SECRET, null, KeyDriverException::class, 'must match'],
    'overlong label' => ['k', Algorithm::HmacSha256, PARTNER_SECRET, str_repeat('l', 192), KeyDriverException::class, 'at most 191'],
    'label that is not UTF-8' => ['k', Algorithm::HmacSha256, PARTNER_SECRET, "caf\xE9", KeyDriverException::class, 'valid UTF-8'],
    'short HMAC secret' => ['k', Algorithm::HmacSha256, 'base64:'.base64_encode(str_repeat('a', 31)), null, InvalidKeyMaterialException::class, 'at least 32'],
    'raw passphrase' => ['k', Algorithm::HmacSha256, 'correct horse battery staple, very long', null, InvalidKeyMaterialException::class, 'PEM block or "base64:'],
    'malformed base64' => ['k', Algorithm::Ed25519, 'base64:!!!', null, InvalidKeyMaterialException::class, 'not canonical'],
    'PEM for an HMAC key' => ['k', Algorithm::HmacSha256, "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA".str_repeat('A', 43)."=\n-----END PUBLIC KEY-----", null, InvalidKeyMaterialException::class, 'cannot be an HMAC secret'],
    'Ed25519 private PEM' => ['k', Algorithm::Ed25519, "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", null, InvalidKeyMaterialException::class, 'only an Ed25519 public key is accepted as PEM'],
    'Ed25519 PEM of another key type' => ['k', Algorithm::Ed25519, pem('PUBLIC KEY', str_repeat("\x01", 44)), null, InvalidKeyMaterialException::class, 'not an Ed25519 public key'],
    'Ed25519 PEM with broken base64' => ['k', Algorithm::Ed25519, "-----BEGIN PUBLIC KEY-----\nMCo=BQ\n-----END PUBLIC KEY-----", null, InvalidKeyMaterialException::class, 'not canonical'],
]);

it('refuses an unknown ring through the action form too', function (): void {
    expect(fn () => Sentinel::importKey(new ImportKeyRequest('nowhere', 'k', Algorithm::HmacSha256, PARTNER_SECRET)))
        ->toThrow(SealingMisconfiguredException::class, 'Key ring [nowhere] is not configured');
});

it('binds the imported status into the envelope', function (): void {
    Event::fake([KeyIntegrityViolated::class]);
    Sentinel::keys()->ring('http')->import('bound', Algorithm::HmacSha256, PARTNER_SECRET);

    DB::table('sentinel_keys')->where('kid', 'bound')->update(['status' => 'active']);
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::keys()->ring('http')->find('bound'))->toBeNull()
        ->and(fn () => Sentinel::signatures()->sign(new PsrRequest('GET', 'https://partner.example/'), 'bound'))->toThrow(UnknownKeyException::class, 'has no key [bound]');

    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->keyId === 'bound');
});

it('revokes an imported key, and the configured revocation list still wins', function (): void {
    partnerRing();
    $request = received(signedPartnerRequest(uri: 'https://api.example.com/events'));
    config()->set('sentinel.keys.rings.http.driver', 'database');
    app(KeyStoreManager::class)->flush();

    // signedPartnerRequest() signs with kid "partner".
    Sentinel::keys()->ring('http')->import('partner', Algorithm::HmacSha256, PARTNER_SECRET);
    config()->set('sentinel.keys.revoked', 'http:partner');
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::keys()->ring('http')->find('partner')?->status)->toBe(KeyStatus::Revoked)
        ->and(fn () => Sentinel::signatures()->verify($request))->toThrow(fn (HttpSignatureException $exception) => expect($exception->reason())->toBe(SignatureRejection::RevokedKey));

    config()->set('sentinel.keys.revoked', '');
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring('http')->revoke('partner', 'contract ended');

    expect(Sentinel::keys()->ring('http')->find('partner')?->status)->toBe(KeyStatus::Revoked);
});

it('activates an imported key later when asked to', function (): void {
    $info = Sentinel::keys()->ring('http')->import('later', Algorithm::HmacSha256, PARTNER_SECRET, signing: true, activatesAt: now()->addDay());

    expect($info->status)->toBe(KeyStatus::Pending)
        ->and($info->canSign)->toBeFalse();

    $this->travel(2)->days();
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::keys()->ring('http')->find('later')?->status)->toBe(KeyStatus::Active);
});

it('records the authenticated actor on the event', function (): void {
    Event::fake([KeyImported::class]);
    $admin = User::query()->create(['name' => 'Admin']);
    $this->actingAs($admin);

    Sentinel::keys()->ring('http')->import('by-admin', Algorithm::HmacSha256, PARTNER_SECRET);

    Event::assertDispatched(KeyImported::class, static fn (KeyImported $event): bool => $event->actorType === $admin->getMorphClass() && (string) $event->actorId === (string) $admin->getKey());
});

it('never lets the material out of the request object, the event, an exception or the inventory', function (): void {
    Event::fake([KeyImported::class]);
    $secret = substr(PARTNER_SECRET, 7);
    $request = new ImportKeyRequest('http', 'hygiene', Algorithm::HmacSha256, PARTNER_SECRET);

    Sentinel::importKey($request);

    try {
        Sentinel::importKey(new ImportKeyRequest('http', 'hygiene-2', Algorithm::HmacSha256, 'base64:'.base64_encode('short but secret')));
    } catch (InvalidKeyMaterialException $exception) {
        expect($exception->getMessage())->not->toContain('short but secret')->not->toContain(base64_encode('short but secret'));
    }

    expect(print_r($request, true))->not->toContain($secret)->toContain('[redacted]')
        ->and(fn () => serialize($request))->toThrow(LogicException::class)
        ->and(fn () => unserialize('O:'.strlen(ImportKeyRequest::class).':"'.ImportKeyRequest::class.'":0:{}'))->toThrow(LogicException::class)
        ->and(serialize(Event::dispatched(KeyImported::class)->all()))->not->toContain($secret)
        ->and(serialize(Sentinel::keys()->ring('http')->all()))->not->toContain($secret)
        ->and(DB::table('sentinel_keys')->where('kid', 'hygiene')->value('envelope'))->not->toContain($secret);
});

it('imports under the fake with the production validation, and asserts it', function (): void {
    $fake = Sentinel::fake();
    $owner = User::query()->create(['name' => 'Acme']);

    fails(fn () => $fake->assertKeyImported(), 'Expected a key to be imported, but none was.');

    $info = Sentinel::keys()->ring('http')->import('acme', Algorithm::Ed25519, (string) KeyMaterial::generate(Algorithm::Ed25519)->encodedPublic(), owner: $owner);
    $signing = Sentinel::importKey(new ImportKeyRequest('http', 'own', Algorithm::HmacSha256, PARTNER_SECRET, signing: true));

    expect($info->status)->toBe(KeyStatus::VerifyOnly)
        ->and($info->ownerType)->toBe($owner->getMorphClass())
        ->and($signing->status)->toBe(KeyStatus::Active)
        ->and(Key::query()->count())->toBe(0)
        ->and(fn () => Sentinel::keys()->ring('http')->import('bad kid', Algorithm::HmacSha256, PARTNER_SECRET))->toThrow(KeyDriverException::class)
        ->and(fn () => Sentinel::keys()->ring('http')->import('k', Algorithm::HmacSha512, PARTNER_SECRET))->toThrow(AlgorithmNotAllowedException::class)
        ->and(fn () => Sentinel::keys()->ring('http')->import('k', Algorithm::HmacSha256, PARTNER_SECRET, label: str_repeat('l', 192)))->toThrow(KeyDriverException::class)
        ->and(fn () => Sentinel::keys()->ring('http')->import('k', Algorithm::HmacSha256, 'passphrase'))->toThrow(InvalidKeyMaterialException::class);

    partnerRing();

    expect(fn () => Sentinel::keys()->ring('http')->import('k', Algorithm::HmacSha256, PARTNER_SECRET))->toThrow(KeyDriverException::class, 'has no database driver');

    $fake->assertKeyImported();
    $fake->assertKeyImported('http');
    $fake->assertKeyImported('http', 'acme');
    Sentinel::assertKeyImported(keyId: 'own');
    fails(fn () => $fake->assertKeyImported('default'), 'into ring [default]');
    fails(fn () => $fake->assertKeyImported('http', 'nope'), 'into ring [http] as [nope]');
    fails(fn () => $fake->assertNoKeyChanges(), 'Expected no key changes');
});

it('reports the owner of a VerifiedSignature for an imported database key', function (): void {
    $partner = User::query()->create(['name' => 'Acme']);
    partnerRing();
    $request = received(signedPartnerRequest());
    config()->set('sentinel.keys.rings.http.driver', 'database');
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring('http')->import('partner', Algorithm::HmacSha256, PARTNER_SECRET, owner: $partner);

    $signature = Sentinel::signatures()->verify($request);

    expect($signature)->toBeInstanceOf(VerifiedSignature::class)
        ->and($signature->ownerType)->toBe($partner->getMorphClass())
        ->and((string) $signature->ownerId)->toBe((string) $partner->getKey());
});

it('fails assertKeyImported on an untouched fake', function (): void {
    Sentinel::fake()->assertKeyImported('http');
})->throws(ExpectationFailedException::class, 'Expected a key to be imported into ring [http], but none was.');
