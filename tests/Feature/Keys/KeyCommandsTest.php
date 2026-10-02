<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\User;
use RoundlyConsulting\Sentinel\Tests\TestCase;

it('prints config key lines to stdout with a secrecy warning', function (): void {
    $this->artisan('sentinel:key:generate', ['--algorithm' => 'hmac-sha512', '--kid' => 'cli-key'])
        ->expectsOutputToContain('Treat these lines as secrets')
        ->expectsOutputToContain('SENTINEL_KEY_ID=cli-key')
        ->expectsOutputToContain('SENTINEL_ALGORITHM=hmac-sha512')
        ->assertSuccessful();

    expect(Key::query()->count())->toBe(0);
});

it('warns when the ring would never read the printed config key', function (): void {
    $this->artisan('sentinel:key:generate', ['--ring' => 'http'])
        ->expectsOutputToContain('does not read config keys')
        ->assertSuccessful();
});

it('stores a database key and prints only its id and public key', function (): void {
    $owner = User::query()->create(['name' => 'Partner']);

    $this->artisan('sentinel:key:generate', [
        '--ring' => 'http', '--algorithm' => 'ed25519', '--kid' => 'partner-a', '--database' => true,
        '--activate-at' => '2026-10-02 10:00:00', '--owner-type' => User::class, '--owner-id' => (string) $owner->getKey(), '--label' => 'Partner A',
    ])
        ->expectsOutputToContain('Stored key [http:partner-a] (ed25519)')
        ->expectsOutputToContain('Public key: base64:')
        ->doesntExpectOutputToContain('SENTINEL_')
        ->assertSuccessful();

    expect((string) Key::query()->where('kid', 'partner-a')->value('owner_id'))->toBe((string) $owner->getKey())
        ->and(Key::query()->where('kid', 'partner-a')->firstOrFail()->activates_at->format('Y-m-d H:i:s e'))->toBe('2026-10-02 10:00:00 UTC');
});

it('fails cleanly on bad generate input', function (array $options, string $message): void {
    $this->artisan('sentinel:key:generate', $options)->expectsOutputToContain($message)->assertFailed();
})->with([
    'unknown algorithm' => [['--algorithm' => 'none'], 'Unknown --algorithm'],
    'missing owner' => [['--owner-type' => User::class, '--owner-id' => '999'], 'model was not found'],
    'not a model' => [['--owner-type' => 'stdClass', '--owner-id' => '1'], 'model was not found'],
    'ring refuses the algorithm' => [['--ring' => 'http', '--algorithm' => 'hmac-sha384'], 'not allowed in key ring [http]'],
    'unknown ring' => [['--ring' => 'nope'], 'not configured'],
]);

it('rotates a database ring and a config ring', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'first');

    $this->artisan('sentinel:key:rotate', ['--ring' => 'http'])
        ->expectsOutputToContain('New signing key [http:')
        ->expectsOutputToContain('Previous key [first] is now verify-only')
        ->assertSuccessful();

    $this->artisan('sentinel:key:rotate', ['--algorithm' => 'ed25519'])
        ->expectsOutputToContain('Treat these lines as secrets')
        ->expectsOutputToContain('SENTINEL_PREVIOUS_KEYS="test-default|hmac-sha256|')
        ->assertSuccessful();

    $this->artisan('sentinel:key:rotate', ['--algorithm' => 'nope'])->expectsOutputToContain('Unknown --algorithm')->assertFailed();
    $this->artisan('sentinel:key:rotate', ['--ring' => 'http', '--algorithm' => 'hmac-sha512'])->expectsOutputToContain('not allowed')->assertFailed();
});

it('revokes database keys and prints the revocation line for config keys', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'partner');
    config()->set('sentinel.keys.revoked', 'http:older');

    $this->artisan('sentinel:key:revoke', ['kid' => 'partner', '--ring' => 'http', '--reason' => 'Contract ended'])
        ->expectsOutputToContain('Revoked key [http:partner]')
        ->assertSuccessful();

    expect(Sentinel::findKey('http', 'partner')?->status)->toBe(KeyStatus::Revoked);

    $this->artisan('sentinel:key:revoke', ['kid' => TestCase::ROOT_KEY_ID, '--reason' => 'Leaked'])
        ->expectsOutputToContain('SENTINEL_REVOKED_KEYS="http:older,default:test-default"')
        ->assertSuccessful();

    $this->artisan('sentinel:key:revoke', ['kid' => 'partner', '--ring' => 'http'])->expectsOutputToContain('--reason is required')->assertFailed();
    $this->artisan('sentinel:key:revoke', ['kid' => 'nope', '--ring' => 'http', '--reason' => 'x'])->expectsOutputToContain('has no key [nope]')->assertFailed();
    $this->artisan('sentinel:key:revoke', ['kid' => 'x', '--ring' => 'nope', '--reason' => 'x'])->expectsOutputToContain('not configured')->assertFailed();
});

it('retires database keys and explains config keys', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, 'old');

    $this->artisan('sentinel:key:retire', ['kid' => 'old', '--ring' => 'http'])->expectsOutputToContain('Retired key [http:old]')->assertSuccessful();
    $this->artisan('sentinel:key:retire', ['kid' => TestCase::ROOT_KEY_ID])->expectsOutputToContain('SENTINEL_PREVIOUS_KEYS')->assertSuccessful();
    $this->artisan('sentinel:key:retire', ['kid' => 'nope', '--ring' => 'http'])->expectsOutputToContain('has no key [nope]')->assertFailed();
    $this->artisan('sentinel:key:retire', ['kid' => 'x', '--ring' => 'nope'])->expectsOutputToContain('not configured')->assertFailed();
});

it('lists keys without ever printing material, and warns on duplicate kids', function (): void {
    Sentinel::keys()->ring('http')->generate(Algorithm::Ed25519, 'partner');

    expect(Artisan::call('sentinel:key:list'))->toBe(0);

    $output = Artisan::output();

    expect($output)->toContain('test-default')->toContain('partner')->toContain('hmac-sha256')->toContain('ed25519')
        ->not->toContain('AQIDBAUG')->not->toContain('base64:');

    config()->set('sentinel.keys.rings.http.driver', 'chain');
    config()->set('sentinel.keys.rings.http.key_id', 'partner');
    config()->set('sentinel.keys.rings.http.key', TestCase::ROOT_KEY);
    app(KeyStoreManager::class)->flush();

    $this->artisan('sentinel:key:list', ['--ring' => 'http'])->expectsOutputToContain('more than one driver')->assertSuccessful();
    $this->artisan('sentinel:key:list', ['--ring' => 'nope'])->expectsOutputToContain('not configured')->assertFailed();
});

it('refuses to retire a key that seals still use, unless forced', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'chain');
    config()->set('sentinel.keys.rings.default.drivers', ['database', 'config']);
    Sentinel::keys()->ring()->generate(Algorithm::HmacSha256, 'in-use');
    invoice();

    $this->artisan('sentinel:key:retire', ['kid' => 'in-use'])->expectsOutputToContain('2 seal(s) still use key [default:in-use]')->assertFailed();
    $this->artisan('sentinel:key:list')->expectsOutputToContain('in-use')->assertSuccessful();
    $this->artisan('sentinel:key:retire', ['kid' => 'in-use', '--force' => true])->expectsOutputToContain('Retired key [default:in-use]')->assertSuccessful();
});

/**
 * I-1: sentinel:key:import — material from a file or a hidden prompt, never an argument.
 */
it('imports a partner key from a PEM file, bound to its owner, printing no material', function (): void {
    $owner = User::query()->create(['name' => 'Acme']);
    $material = KeyMaterial::generate(Algorithm::EcdsaP256Sha256);
    $pem = (string) base64_decode(substr((string) $material->encodedPublic(), 7), true);
    $file = tempnam(sys_get_temp_dir(), 'sentinel-import-');
    file_put_contents((string) $file, $pem);

    try {
        $this->artisan('sentinel:key:import', [
            'kid' => 'acme-2026-10', '--ring' => 'http', '--algorithm' => 'ecdsa-p256-sha256', '--file' => $file,
            '--owner-type' => User::class, '--owner-id' => (string) $owner->getKey(), '--label' => 'Acme', '--activate-at' => '2026-10-02 10:00:00',
        ])
            ->expectsOutputToContain('Imported key [http:acme-2026-10] (ecdsa-p256-sha256)')
            ->expectsOutputToContain('verify_only')
            ->expectsOutputToContain(User::class.':'.$owner->getKey())
            ->doesntExpectOutputToContain('BEGIN PUBLIC KEY')
            ->doesntExpectOutputToContain('base64:')
            ->assertExitCode(0);
    } finally {
        unlink((string) $file);
    }

    expect(Sentinel::keys()->ring('http')->find('acme-2026-10')?->label)->toBe('Acme');
});

it('reads the material from a hidden prompt, and imports a signing key with --signing', function (): void {
    $this->artisan('sentinel:key:import', ['kid' => 'own-http', '--ring' => 'http', '--algorithm' => 'hmac-sha256', '--signing' => true])
        ->expectsQuestion('Key material (base64:…; use --file for PEM)', PARTNER_SECRET)
        ->expectsOutputToContain('Imported key [http:own-http] (hmac-sha256)')
        ->expectsOutputToContain('active')
        ->doesntExpectOutputToContain(substr(PARTNER_SECRET, 7, 20))
        ->assertExitCode(0);

    expect(Sentinel::keys()->ring('http')->find('own-http')?->status)->toBe(KeyStatus::Active);
});

it('refuses bad import input with exit 2, and a refused import with exit 1', function (): void {
    $this->artisan('sentinel:key:import', ['kid' => 'k', '--ring' => 'http', '--algorithm' => 'hmac-sha256', '--no-interaction' => true])
        ->expectsOutputToContain('Pass the material with --file')
        ->assertExitCode(2);

    $this->artisan('sentinel:key:import', ['kid' => 'k', '--ring' => 'http'])->expectsOutputToContain('A valid --algorithm is required')->assertExitCode(2);
    $this->artisan('sentinel:key:import', ['kid' => 'k', '--ring' => 'http', '--algorithm' => 'rsa'])->assertExitCode(2);
    $this->artisan('sentinel:key:import', ['kid' => 'k', '--ring' => 'http', '--algorithm' => 'hmac-sha256', '--file' => '/nonexistent/sentinel.pem'])
        ->expectsOutputToContain('The --file is missing, unreadable, empty or larger than 64 KB')
        ->assertExitCode(2);
    $this->artisan('sentinel:key:import', ['kid' => 'k', '--ring' => 'http', '--algorithm' => 'hmac-sha256', '--owner-type' => User::class, '--owner-id' => '999'])
        ->expectsOutputToContain('model was not found')
        ->assertExitCode(2);
    $this->artisan('sentinel:key:import', ['kid' => 'k', '--ring' => 'http', '--algorithm' => 'hmac-sha256'])
        ->expectsQuestion('Key material (base64:…; use --file for PEM)', '')
        ->expectsOutputToContain('No key material was given')
        ->assertExitCode(2);
    $this->artisan('sentinel:key:import', ['kid' => 'k', '--ring' => 'http', '--algorithm' => 'hmac-sha256'])
        ->expectsQuestion('Key material (base64:…; use --file for PEM)', 'a passphrase, never key material')
        ->expectsOutputToContain('must be a PEM block or "base64:')
        ->doesntExpectOutputToContain('a passphrase, never key material')
        ->assertExitCode(1);

    expect(Key::query()->count())->toBe(0);
});
