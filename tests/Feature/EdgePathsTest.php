<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\Request as PsrRequest;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedNonce;
use RoundlyConsulting\Sentinel\Enums\TypeKind;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Messages\PsrRequestView;
use RoundlyConsulting\Sentinel\Models\Nonce;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\SentinelServiceProvider;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Definitions\PartyIdentitySeal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

/**
 * Smaller paths of the public surface that the feature suites do not reach on their own.
 */
it('redacts nonce values from dumps and refuses to revive an issued nonce from serialized data', function (): void {
    $request = new ConsumeNonceRequest('password-reset', 'secret-nonce-value', invoice());
    $class = IssuedNonce::class;

    expect(print_r($request, true))->not->toContain('secret-nonce-value')->toContain('[redacted]')->toContain(Invoice::class)
        ->and(print_r(new ConsumeNonceRequest('login', 'secret-nonce-value'), true))->not->toContain('secret-nonce-value')
        ->and(fn () => unserialize('O:'.strlen($class).':"'.$class.'":0:{}'))->toThrow(LogicException::class, 'cannot be unserialized');
});

it('warns when sentinel:verify lists fewer findings than it found', function (): void {
    $first = invoice();
    $second = invoice();
    DB::table('invoices')->whereIn('id', [$first->id, $second->id])->update(['amount' => '0.00']);

    expect(Artisan::call('sentinel:verify', ['model' => [Invoice::class], '--seal' => 'financial', '--max-findings' => 1]))->toBe(1)
        ->and(Artisan::output())->toContain('More findings exist than --max-findings lists.');
});

it('has no ledger head before the first checkpoint', function (): void {
    expect(Sentinel::ledger()->head())->toBeNull();

    invoice();
    Sentinel::checkpoint();

    expect(Sentinel::ledger()->head()?->seq)->toBe(1);
});

it('records no actor when no authentication service is bound', function (): void {
    app()->offsetUnset('auth');

    expect(app(Runtime::class)->user())->toBeNull();
});

it('lets inline fields refine and extend a reusable definition', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('party')
        ->using(PartyIdentitySeal::class)
        ->string('number')
        ->computed('lines', static fn (): array => ['n' => 1]));

    $fields = array_map(static fn (array $field): string => implode('=', $field), Sentinel::model($class)->definition()->manifest());

    expect($fields)->toContain('a:number='.TypeKind::String->value)
        ->toContain('c:lines='.TypeKind::Auto->value)
        ->toContain('a:secret='.TypeKind::Plaintext->value);
});

it('has no status line on a request view', function (): void {
    expect((new PsrRequestView(new PsrRequest('GET', 'https://api.example.com/')))->status())->toBeNull();
});

it('treats a remembered client nonce whose expiry is unreadable as still live', function (): void {
    $until = Clock::now()->addMinutes(5);

    expect(Sentinel::nonces())->not->toBeNull()
        ->and(app(NonceStore::class)->remember('http:partner', NonceDigest::of('n-1'), $until, Clock::now()))->toBeTrue();

    if (! corrupt(static fn () => Nonce::query()->toBase()->update(['expires_at' => 'garbled']))) {
        return;
    }

    expect(app(NonceStore::class)->remember('http:partner', NonceDigest::of('n-1'), $until, Clock::now()))->toBeFalse();
});

it('accepts a lock-capable cache store for nonces at boot', function (): void {
    config()->set('sentinel.nonces.store', 'cache');
    config()->set('sentinel.nonces.cache_store', 'array');

    app()->getProvider(SentinelServiceProvider::class)?->boot();

    $nonce = Sentinel::nonces()->issue('download');

    expect(Sentinel::nonces()->consume('download', $nonce->value))->toBeTrue()
        ->and(Sentinel::nonces()->consume('download', $nonce->value))->toBeFalse();
});
