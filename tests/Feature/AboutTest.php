<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\TestCase;

/**
 * The `php artisan about` section, pinned with testing-for-laravel's render check (it proves
 * the capture is not empty before trusting anything). Rows are presence/flags only — the
 * configured root key must never render, raw or encoded. The Manager row disambiguates
 * from laravel/sentinel's own manager.
 */
it('renders its about section without leaking key material', function (): void {
    $edSecret = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
    config()->set('sentinel.keys.rings.http.previous', 'partner|ed25519|base64:'.base64_encode($edSecret));

    expect('sentinel')->toLeakNoSecrets(
        [substr(TestCase::ROOT_KEY, 7), TestCase::ROOT_KEY, base64_decode(substr(TestCase::ROOT_KEY, 7)), base64_encode($edSecret)],
        mustRender: [
            'Default ring / driver', 'default (config)', 'Rings', 'default, http', 'Auto-seal', 'ON',
            'Tampered writes', 'refuse', 'Ledger', 'Anchors', 'none (whole-database rollback undetectable)',
            'Sealable models', '0 configured, 0 discovered', 'Idempotency store', 'database', 'Nonce store', 'Signature profiles', 'Manager', SentinelManager::class,
        ],
    );
});

it('reports flags the way the environment means them', function (): void {
    config()->set('sentinel.sealing.auto', 'off');
    config()->set('sentinel.ledger.enabled', 'no');
    config()->set('sentinel.sealing.on_tampered_write', 'reseal');

    config()->set('sentinel.ledger.anchors', 'cache,log');
    config()->set('sentinel.models', [Invoice::class]);

    Artisan::call('about', ['--only' => 'sentinel']);

    expect(Artisan::output())->toMatch('/Auto-seal\W+OFF/')->toMatch('/Ledger\W+OFF/')->toMatch('/Tampered writes\W+reseal/')
        ->toMatch('/Anchors\W+cache, log/')->toMatch('/Sealable models\W+1 configured, 0 discovered/');
});

it('reports invalid configuration instead of failing about', function (): void {
    config()->set('sentinel.keys.default_ring', 'Bad Ring');

    Artisan::call('about', ['--only' => 'sentinel']);

    expect(Artisan::output())->toContain('invalid configuration');
});
