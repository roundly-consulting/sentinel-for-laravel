<?php

declare(strict_types=1);

use Illuminate\Contracts\Http\Kernel;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifyHttpSignature;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;

/**
 * I-13: who signed this request — the verified signature and its key's owner, typed.
 */
afterEach(function (): void {
    Relation::morphMap([], false);
});

/**
 * A partner request signed with the shared secret, received after the partner's key moved
 * into the database (owned by `$owner` when given).
 */
function ownedPartnerRequest(?User $owner): Request
{
    partnerRing();
    $request = received(signedPartnerRequest());
    config()->set('sentinel.keys.rings.http.driver', 'database');
    app(KeyStoreManager::class)->flush();
    Sentinel::keys()->ring('http')->import('partner', Algorithm::HmacSha256, PARTNER_SECRET, owner: $owner);

    return $request;
}

it('reads nothing from a request the middleware did not verify', function (): void {
    $request = Request::create('/events', 'POST');

    expect(Sentinel::signatures()->current($request))->toBeNull()
        ->and(Sentinel::signatures()->owner($request))->toBeNull()
        ->and(app(SentinelManager::class)->verifiedSignature($request))->toBeNull();

    $request->attributes->set(VerifyHttpSignature::ATTRIBUTE, 'not a signature');

    expect(Sentinel::verifiedSignature($request))->toBeNull();
});

it('reads the verified signature and its owner inside a signed route', function (): void {
    $partner = User::query()->create(['name' => 'Acme']);
    $request = ownedPartnerRequest($partner);

    Route::post('/events', static fn (Request $received): array => [
        'key' => Sentinel::signatures()->current($received)?->keyId,
        'owner' => Sentinel::signatures()->owner($received)?->getKey(),
        'via-signature' => Sentinel::signatureOwner(Sentinel::verifiedSignature($received) ?? throw new LogicException)?->getKey(),
    ])->middleware('sentinel.signed');

    $response = app(Kernel::class)->handle($request);

    expect($response->getStatusCode())->toBe(200)
        ->and(json_decode((string) $response->getContent(), true))->toBe(['key' => 'partner', 'owner' => $partner->getKey(), 'via-signature' => $partner->getKey()]);
});

it('returns no owner for a config key, an unowned key, or an owner that is gone', function (): void {
    partnerRing();
    $signature = Sentinel::signatures()->verify(received(signedPartnerRequest()));

    expect($signature->ownerType)->toBeNull()
        ->and(Sentinel::signatures()->owner($signature))->toBeNull();

    $unowned = new VerifiedSignature('sig1', 'http', 'k', Algorithm::HmacSha256, 1, null, null, null, []);
    $vanished = new VerifiedSignature('sig1', 'http', 'k', Algorithm::HmacSha256, 1, null, null, null, [], User::class, 999);
    $unknownType = new VerifiedSignature('sig1', 'http', 'k', Algorithm::HmacSha256, 1, null, null, null, [], 'App\\Models\\Gone', 1);

    expect(Sentinel::signatures()->owner($unowned))->toBeNull()
        ->and(Sentinel::signatures()->owner($vanished))->toBeNull()
        ->and(Sentinel::signatures()->owner($unknownType))->toBeNull();
});

it('resolves an owner stored under a morph alias', function (): void {
    Relation::morphMap(['partner' => User::class]);
    $partner = User::query()->create(['name' => 'Aliased']);
    $request = ownedPartnerRequest($partner);

    $signature = Sentinel::signatures()->verify($request);

    expect($signature->ownerType)->toBe('partner')
        ->and(Sentinel::signatures()->owner($signature)?->is($partner))->toBeTrue();
});

it('reads accessors under the fake as in production', function (): void {
    $partner = User::query()->create(['name' => 'Faked']);
    $fake = Sentinel::fake();
    $fake->fakeVerifiedSignature(new VerifiedSignature('sig1', 'http', 'acme', Algorithm::Ed25519, 1, null, null, null, [], User::class, $partner->getKey()));

    Route::post('/events', static fn (Request $received): array => [
        'owner' => Sentinel::signatures()->owner($received)?->getKey(),
    ])->middleware('sentinel.signed');

    expect($this->postJson('/events')->json('owner'))->toBe($partner->getKey());
});
