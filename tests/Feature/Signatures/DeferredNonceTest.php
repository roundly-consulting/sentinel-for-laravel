<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Actions\Signatures\CommitSignatureNonceAction;
use RoundlyConsulting\Sentinel\Actions\Signatures\VerifyRequestSignatureDeferredAction;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\DeferredSignature;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Events\HttpSignatureRejected;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Signatures\SignatureVerifier;
use RoundlyConsulting\Sentinel\Models\Nonce;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\RecordedCall;

/**
 * Verify now, commit the nonce later (owner, 2026-11-08): a consumer that verifies a request
 * and then refuses it for its own reasons (a 400, a 500) must not burn the nonce, or the
 * sender's identical retry is `replayed` forever.
 */
beforeEach(function (): void {
    partnerRing();
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000));
});

afterEach(fn () => Carbon::setTestNow());

function useNonceStore(string $store): void
{
    if ($store === 'cache') {
        config()->set('sentinel.nonces.store', 'cache');
        config()->set('sentinel.nonces.cache_store', 'array');
        app()->forgetInstance(NonceStore::class);
    }
}

function deferredRejection(Closure $call): ?SignatureRejection
{
    try {
        $call();

        return null;
    } catch (HttpSignatureException $exception) {
        return $exception->reason();
    }
}

it('verifies everything but leaves the nonce unused', function (string $store): void {
    useNonceStore($store);
    $signed = signedPartnerRequest();

    $first = Sentinel::signatures()->verifyDeferred(received($signed));
    $second = Sentinel::signatures()->verifyDeferred(received($signed));

    expect($first)->toBeInstanceOf(DeferredSignature::class)
        ->and($first->signature->keyId)->toBe('partner')
        ->and($first->signature->nonce)->not->toBeNull()
        ->and($first->hasNonce())->toBeTrue()
        ->and($first->nonceUntil)->toBe(1_800_000_000 + 300 + 30 + 1)
        ->and($first->method)->toBe('POST')
        ->and($first->path)->toBe('/events')
        ->and($second->signature->nonce)->toBe($first->signature->nonce)
        ->and(Nonce::query()->count())->toBe(0);

    // Nothing was recorded: the eager path still accepts it once.
    expect(Sentinel::signatures()->verify(received($signed))->nonce)->toBe($first->signature->nonce);
})->with(['database', 'cache']);

it('marks the nonce used on commit, so the next copy is a replay', function (string $store): void {
    useNonceStore($store);
    $signed = signedPartnerRequest();

    $deferred = Sentinel::signatures()->verifyDeferred(received($signed));
    $committed = Sentinel::signatures()->commitNonce($deferred);

    expect($committed)->toBe($deferred->signature)
        ->and(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(received($signed))))->toBe(SignatureRejection::Replayed)
        ->and(deferredRejection(fn () => Sentinel::signatures()->verify(received($signed))))->toBe(SignatureRejection::Replayed);
})->with(['database', 'cache']);

it('refuses a nonce the eager path already recorded', function (string $store): void {
    useNonceStore($store);
    $signed = signedPartnerRequest();

    Sentinel::signatures()->verify(received($signed));

    expect(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(received($signed))))->toBe(SignatureRejection::Replayed);
})->with(['database', 'cache']);

it('commits a nonce exactly once: the second commit is a replay', function (string $store): void {
    useNonceStore($store);
    Event::fake([HttpSignatureRejected::class]);
    $signed = signedPartnerRequest();

    $one = Sentinel::signatures()->verifyDeferred(received($signed));
    $two = Sentinel::signatures()->verifyDeferred(received($signed));

    Sentinel::signatures()->commitNonce($one);

    expect(deferredRejection(fn () => Sentinel::signatures()->commitNonce($two)))->toBe(SignatureRejection::Replayed)
        ->and(deferredRejection(fn () => Sentinel::signatures()->commitNonce($one)))->toBe(SignatureRejection::Replayed);

    Event::assertDispatchedTimes(HttpSignatureRejected::class, 2);
    Event::assertDispatched(HttpSignatureRejected::class, static fn (HttpSignatureRejected $event): bool => $event->reason === SignatureRejection::Replayed
        && $event->keyId === 'partner' && $event->method === 'POST' && $event->path === '/events');
})->with(['database', 'cache']);

it('records the nonce under the eager path\'s scope and lifetime', function (): void {
    $eager = signedPartnerRequest();
    Sentinel::signatures()->verify(received($eager));
    $eagerRow = Nonce::query()->sole();
    $eagerRow->delete();

    $deferred = signedPartnerRequest();
    Sentinel::signatures()->commitNonce(Sentinel::signatures()->verifyDeferred(received($deferred)));
    $deferredRow = Nonce::query()->sole();

    expect($deferredRow->purpose)->toBe($eagerRow->purpose)
        ->and($deferredRow->purpose)->toStartWith('http:')
        ->and($deferredRow->expires_at->getTimestamp())->toBe($eagerRow->expires_at->getTimestamp())
        ->and($deferredRow->expires_at->getTimestamp())->toBe(1_800_000_331)
        ->and($deferredRow->kind)->toBe($eagerRow->kind);
});

it('holds a committed nonce for the whole last second of the window, as the eager path does', function (string $store): void {
    useNonceStore($store);
    $signed = Sentinel::signatures()->sign(new PsrRequest('POST', 'https://api.example.com/events', ['Content-Type' => 'application/json'], '{"a":1}'), 'partner');

    Sentinel::signatures()->commitNonce(Sentinel::signatures()->verifyDeferred(received($signed)));

    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000)->addMicroseconds(330_400_000));

    expect(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(received($signed))))->toBe(SignatureRejection::Replayed);

    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_331));

    expect(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(received($signed))))->toBe(SignatureRejection::TooOld);
})->with(['database', 'cache']);

it('refuses to commit once the window closed, so two late commits can never both win', function (string $store): void {
    useNonceStore($store);
    Event::fake([HttpSignatureRejected::class]);
    $signed = signedPartnerRequest();

    $one = Sentinel::signatures()->verifyDeferred(received($signed));
    $two = Sentinel::signatures()->verifyDeferred(received($signed));

    // The last instant the window accepts: a commit still lands.
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_000)->addMicroseconds(330_999_999));
    Sentinel::signatures()->commitNonce($one);

    // From the first instant past it, a commit is too old — even for a nonce nobody committed.
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_331));

    expect(deferredRejection(fn () => Sentinel::signatures()->commitNonce($two)))->toBe(SignatureRejection::TooOld);

    $late = Sentinel::signatures()->verifyDeferred(received(signedPartnerRequest()));
    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_331 + 300 + 30 + 1));

    expect(deferredRejection(fn () => Sentinel::signatures()->commitNonce($late)))->toBe(SignatureRejection::TooOld)
        ->and(Nonce::query()->count())->toBe($store === 'database' ? 1 : 0);

    Event::assertDispatched(HttpSignatureRejected::class, static fn (HttpSignatureRejected $event): bool => $event->reason === SignatureRejection::TooOld);
})->with(['database', 'cache']);

it('commits nothing for a signature without a nonce', function (): void {
    config()->set('sentinel.signatures.profiles.default.require_nonce', false);
    $signed = signedPartnerRequest(new SigningOptions(nonce: false));

    $deferred = Sentinel::signatures()->verifyDeferred(received($signed));

    expect($deferred->signature->nonce)->toBeNull()
        ->and($deferred->hasNonce())->toBeFalse()
        ->and(Sentinel::signatures()->commitNonce($deferred))->toBe($deferred->signature)
        ->and(Sentinel::signatures()->commitNonce($deferred))->toBe($deferred->signature)
        ->and(Nonce::query()->count())->toBe(0);
});

it('rejects exactly what the eager path rejects, firing the event, before any nonce lookup', function (): void {
    Event::fake([HttpSignatureRejected::class]);
    $signed = signedPartnerRequest();
    $tampered = received($signed->withHeader('Content-Type', 'text/plain'));

    expect(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred($tampered)))->toBe(SignatureRejection::InvalidSignature)
        ->and(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(Request::create('/events', 'POST'))))->toBe(SignatureRejection::Missing);

    Event::assertDispatched(HttpSignatureRejected::class, static fn (HttpSignatureRejected $event): bool => $event->reason === SignatureRejection::InvalidSignature && $event->path === '/events');

    // An unknown profile throws what verify() throws.
    expect(fn () => Sentinel::signatures()->verifyDeferred(received($signed), 'nope'))->toThrow(InvalidSentinelConfigurationException::class);
});

it('refuses a bound nonce store that cannot check a nonce without recording it', function (): void {
    app()->instance(NonceStore::class, new class implements NonceStore
    {
        public function issue(string $purpose, string $digest, CarbonImmutable $expiresAt, ?Model $subject): void {}

        public function consume(string $purpose, string $digest, CarbonImmutable $now, ?Model $subject): bool
        {
            return false;
        }

        public function remember(string $purpose, string $digest, CarbonImmutable $until, CarbonImmutable $now): bool
        {
            return true;
        }

        public function prune(CarbonImmutable $now): int
        {
            return 0;
        }
    });

    expect(fn () => Sentinel::signatures()->verifyDeferred(received(signedPartnerRequest())))
        ->toThrow(InvalidSentinelConfigurationException::class, 'InspectsNonces');

    // The eager path does not need the capability.
    expect(Sentinel::signatures()->verify(received(signedPartnerRequest())))->toBeInstanceOf(VerifiedSignature::class);
});

it('treats a corrupt remembered record as live', function (): void {
    $signed = signedPartnerRequest();
    $deferred = Sentinel::signatures()->verifyDeferred(received($signed));
    Sentinel::signatures()->commitNonce($deferred);

    // PostgreSQL and MySQL refuse the corruption itself; the nonce stays recorded and live.
    corrupt(fn () => Nonce::query()->toBase()->update(['expires_at' => 'not a date']));

    expect(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(received($signed))))->toBe(SignatureRejection::Replayed);
});

it('runs one API through the facade, an injected manager and the raw actions', function (): void {
    $facade = Sentinel::verifyRequestSignatureDeferred(received(signedPartnerRequest()));
    $manager = app(SentinelManager::class)->verifyRequestSignatureDeferred(received(signedPartnerRequest()), 'default');
    $action = app(VerifyRequestSignatureDeferredAction::class)->execute(received(signedPartnerRequest()));

    expect(Nonce::query()->count())->toBe(0)
        ->and(Sentinel::commitSignatureNonce($facade))->toBe($facade->signature)
        ->and(app(SentinelManager::class)->commitSignatureNonce($manager))->toBe($manager->signature)
        ->and(app(CommitSignatureNonceAction::class)->execute($action))->toBe($action->signature)
        ->and(Nonce::query()->count())->toBe(3);
});

it('uses the nonce scope the eager path uses', function (): void {
    $deferred = Sentinel::signatures()->verifyDeferred(received(signedPartnerRequest()));
    Sentinel::signatures()->commitNonce($deferred);

    expect(Nonce::query()->sole()->purpose)->toBe(SignatureVerifier::nonceScope('http', 'partner'))
        ->and($deferred->nonceScope)->toBe(SignatureVerifier::nonceScope('http', 'partner'));
});

// ── the fake ─────────────────────────────────────────────────────────────────

it('fakes deferred verification and the commit with the real once-only rule', function (): void {
    $fake = Sentinel::fake();
    $fake->fakeVerifiedSignature(new VerifiedSignature('sig1', 'http', 'acme', Algorithm::Ed25519, 1_800_000_000, null, 'n-1', null, []));

    $one = Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST'));
    $two = Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST'));

    expect($one->signature->keyId)->toBe('acme')
        ->and($one->nonceUntil)->toBe(1_800_000_331)
        ->and($one->path)->toBe('/hooks')
        ->and(Sentinel::signatures()->commitNonce($one))->toBe($one->signature)
        ->and(deferredRejection(fn () => Sentinel::signatures()->commitNonce($two)))->toBe(SignatureRejection::Replayed)
        ->and(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST'))))->toBe(SignatureRejection::Replayed)
        ->and(Nonce::query()->count())->toBe(0);

    $fake->assertSignatureVerifiedDeferred();
    $fake->assertSignatureVerifiedDeferred('default');
    $fake->assertNonceCommitted();
    $fake->assertNonceCommitted('acme');
});

it('records deferred calls without the nonce', function (): void {
    $fake = Sentinel::fake();
    $fake->fakeVerifiedSignature(new VerifiedSignature('sig1', 'http', 'acme', Algorithm::Ed25519, 1_800_000_000, null, 'secret-nonce-value', null, []));

    Sentinel::signatures()->commitNonce(Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST')));

    $commits = $fake->recorded('commitSignatureNonce');

    expect($commits)->toHaveCount(1)
        ->and($commits[0]->arguments)->toBe(['http', 'acme'])
        ->and(serialize(array_map(static fn (RecordedCall $call): mixed => $call->arguments, $commits)))->not->toContain('secret-nonce-value');
});

it('fails each deferred fake assertion when nothing matches', function (): void {
    $fake = Sentinel::fake();

    fails(fn () => $fake->assertSignatureVerifiedDeferred(), 'Expected a signature to be verified with its nonce deferred, but none was.');
    fails(fn () => $fake->assertNonceCommitted(), 'Expected a signature nonce to be committed, but none was.');
    $fake->assertNonceNotCommitted();

    $fake->fakeVerifiedSignature(new VerifiedSignature('sig1', 'http', 'acme', Algorithm::Ed25519, 1_800_000_000, null, 'n-2', null, []));
    $deferred = Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST'));

    fails(fn () => $fake->assertSignatureVerifiedDeferred('partners'), 'Expected a signature to be verified with its nonce deferred against profile [partners], but none was.');
    fails(fn () => $fake->assertNonceCommitted('other'), 'Expected a signature nonce to be committed with key [other], but none was.');

    // A plain verify() is not a deferred one.
    Sentinel::signatures()->verify(Request::create('/hooks', 'POST'));
    $fake->assertSignatureVerified();

    Sentinel::signatures()->commitNonce($deferred);
    $fake->assertNonceNotCommitted('other');

    fails(fn () => $fake->assertNonceNotCommitted(), 'Expected no signature nonce to be committed, but 1 was.');
    fails(fn () => $fake->assertNonceNotCommitted('acme'), 'Expected no signature nonce to be committed with key [acme], but 1 was.');
});

it('does not count a refused commit or a scripted rejection', function (): void {
    $fake = Sentinel::fake();
    $fake->fakeVerifiedSignature(new VerifiedSignature('sig1', 'http', 'acme', Algorithm::Ed25519, 1_800_000_000, null, 'n-3', null, []));
    $deferred = Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST'));

    Carbon::setTestNow(Carbon::createFromTimestampUTC(1_800_000_331));

    expect(deferredRejection(fn () => Sentinel::signatures()->commitNonce($deferred)))->toBe(SignatureRejection::TooOld);
    $fake->assertNonceNotCommitted();

    $fake->rejectSignatures(SignatureRejection::Expired);

    expect(deferredRejection(fn () => Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST'))))->toBe(SignatureRejection::Expired)
        ->and($fake->recorded('verifyRequestSignatureDeferred'))->toHaveCount(2);

    fails(fn () => $fake->assertSignatureVerifiedDeferred('nope'), 'against profile [nope]');
});

it('returns a synthetic deferred signature without a nonce by default', function (): void {
    $fake = Sentinel::fake();

    $deferred = Sentinel::signatures()->verifyDeferred(Request::create('/hooks', 'POST'));

    expect($deferred->signature->keyId)->toBe('fake')
        ->and($deferred->signature->nonce)->toBeNull()
        ->and(Sentinel::signatures()->commitNonce($deferred))->toBe($deferred->signature);

    $fake->assertNonceCommitted('fake');
});
