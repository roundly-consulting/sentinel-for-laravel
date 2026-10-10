<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Events\KeyIntegrityViolated;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;

/**
 * `sentinel:key:reseal` — the upgrade step to label binding: every database key of every
 * database ring re-sealed as `sentinel.key/2` under its row lock, `ring:kid → label` printed
 * before it is bound, a row that fails its integrity check never re-sealed (exit 1).
 */
beforeEach(fn () => macRing());

/**
 * Every stored key's envelope format, by `ring:kid`.
 *
 * @return array<string, string|null>
 */
function storedFormats(): array
{
    $formats = [];

    foreach (DB::table('sentinel_keys')->orderBy('id')->get(['ring', 'kid']) as $row) {
        $formats["{$row->ring}:{$row->kid}"] = envelopeOf((string) $row->ring, (string) $row->kid)['format'] ?? null;
    }

    return $formats;
}

/**
 * Run `sentinel:key:reseal`: its exit code and its whole output (several expectations may
 * concern one line, which `expectsOutputToContain()` cannot match twice).
 *
 * @param  array<string, mixed>  $options
 * @return array{int, string}
 */
function runReseal(array $options = []): array
{
    $code = Artisan::call('sentinel:key:reseal', $options);

    return [$code, Artisan::output()];
}

/**
 * @return list<array<string, mixed>>
 */
function storedKeyRows(): array
{
    return DB::table('sentinel_keys')->orderBy('id')->get()->map(static fn (object $row): array => (array) $row)->all();
}

it('re-seals every legacy key of every database ring, printing ring:kid → label', function (): void {
    legacyKey('http', 'acme', 'ACME billing');
    legacyKey('http', 'bare');
    legacyKey('logs', 'billing-2', 'billing');
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'fresh', label: 'Fresh');

    [$code, $output] = runReseal();

    expect($code)->toBe(0)
        ->and($output)->toMatch('/http:acme → "ACME billing" \.+ binding/u')
        ->toMatch('/http:bare → \(no label\) \.+ binding/u')
        ->toMatch('/logs:billing-2 → "billing" \.+ binding/u')
        ->toMatch('/http:fresh → "Fresh" \.+ already bound/u')
        ->toContain('Re-sealed 3 key(s), 1 already bound.')
        ->toContain('Check the labels above, then set SENTINEL_REQUIRE_BOUND_LABEL=true.')
        ->and(storedFormats())->toBe([
            'http:acme' => 'sentinel.key/2', 'http:bare' => 'sentinel.key/2', 'logs:billing-2' => 'sentinel.key/2', 'http:fresh' => 'sentinel.key/2',
        ])
        ->and(envelopeOf('http', 'acme')['label'] ?? null)->toBe('ACME billing')
        ->and(envelopeOf('logs', 'billing-2')['label'] ?? null)->toBe('billing')
        ->and(app(KeyStoreManager::class)->find('http', 'acme')?->label)->toBe('ACME billing')
        ->and(app(KeyStoreManager::class)->find('logs', 'billing-2')?->label)->toBe('billing');
});

it('keeps every key verifying through the upgrade', function (): void {
    $secret = (string) KeyMaterial::generate(Algorithm::HmacSha256)->encodedPrivate();
    legacyKey('logs', 'billing-2', 'billing', 'verify_only', $secret);
    $message = '{"service":"billing","seq":9}';

    $before = Sentinel::keys()->ring('logs')->verifyMac('billing-2', $message, peerMac($secret, $message));
    runReseal();
    app(KeyStoreManager::class)->flush();
    $after = Sentinel::keys()->ring('logs')->verifyMac('billing-2', $message, peerMac($secret, $message));

    expect($after)->toEqual($before)
        ->and($after->label)->toBe('billing')
        ->and(storedFormats())->toBe(['logs:billing-2' => 'sentinel.key/2']);
});

it('writes nothing with --dry-run', function (): void {
    legacyKey('http', 'acme', 'ACME');
    $before = storedKeyRows();

    [$code, $output] = runReseal(['--dry-run' => true]);

    expect($code)->toBe(0)
        ->and($output)->toMatch('/http:acme → "ACME" \.+ would bind/u')
        ->toContain('Dry run: 1 key(s) would be re-sealed, 0 already bound. Nothing was written.')
        ->not->toContain('SENTINEL_REQUIRE_BOUND_LABEL')
        ->and(storedKeyRows())->toBe($before)
        ->and(storedFormats())->toBe(['http:acme' => 'sentinel.key/1']);
});

it('is idempotent: a second run re-seals nothing and writes nothing', function (): void {
    legacyKey('http', 'acme', 'ACME');
    legacyKey('logs', 'billing-2', 'billing');

    expect(runReseal()[1])->toContain('Re-sealed 2 key(s), 0 already bound.');

    $resealed = storedKeyRows();
    [$code, $output] = runReseal();

    expect($code)->toBe(0)
        ->and($output)->toMatch('/http:acme → "ACME" \.+ already bound/u')
        ->toMatch('/logs:billing-2 → "billing" \.+ already bound/u')
        ->toContain('Re-sealed 0 key(s), 2 already bound.')
        ->and(storedKeyRows())->toBe($resealed);
});

it('never re-seals a key that fails its integrity check, and exits 1', function (): void {
    Event::fake([KeyIntegrityViolated::class]);
    legacyKey('http', 'good', 'ACME');
    legacyKey('http', 'flipped', 'Partner');
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'relabelled', label: 'Fresh');
    DB::table('sentinel_keys')->where('kid', 'flipped')->update(['status' => 'verify_only']);
    DB::table('sentinel_keys')->where('kid', 'relabelled')->update(['label' => 'Evil Corp']);
    $flipped = keyRow('http', 'flipped');
    $relabelled = keyRow('http', 'relabelled');

    [$code, $output] = runReseal();

    expect($code)->toBe(1)
        ->and($output)->toMatch('/http:good → "ACME" \.+ binding/u')
        ->toMatch('/http:flipped[ .]+fails its integrity check — not re-sealed/u')
        ->toMatch('/http:relabelled[ .]+fails its integrity check — not re-sealed/u')
        ->toContain('Re-sealed 1 key(s), 0 already bound.')
        ->toContain('2 key(s) fail their integrity check and were not re-sealed')
        ->not->toContain('Partner')->not->toContain('Evil Corp')->not->toContain('Check the labels above')
        ->and(keyRow('http', 'flipped'))->toBe($flipped)
        ->and(keyRow('http', 'relabelled'))->toBe($relabelled)
        ->and(storedFormats())->toBe(['http:good' => 'sentinel.key/2', 'http:flipped' => null, 'http:relabelled' => null]);

    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->keyId === 'flipped');
    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->keyId === 'relabelled');
});

it('refuses legacy keys while require_bound_label is on, writing nothing', function (): void {
    Event::fake([KeyIntegrityViolated::class]);
    legacyKey('http', 'acme', 'ACME');
    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256, keyId: 'fresh', label: 'Fresh');
    config()->set('sentinel.keys.require_bound_label', true);
    $before = storedKeyRows();

    [$code, $output] = runReseal();

    expect($code)->toBe(1)
        ->and($output)->toMatch('/http:acme[ .]+legacy envelope refused \(require_bound_label is on\) — not re-sealed/u')
        ->toMatch('/http:fresh → "Fresh" \.+ already bound/u')
        ->toContain('1 legacy key(s) were refused: sentinel.keys.require_bound_label is on. Turn it off, run sentinel:key:reseal again, then turn it back on.')
        ->not->toContain('ACME')
        ->and(storedKeyRows())->toBe($before);

    Event::assertDispatched(KeyIntegrityViolated::class, static fn (KeyIntegrityViolated $event): bool => $event->keyId === 'acme');
});

it('limits the run to one ring with --ring', function (): void {
    legacyKey('http', 'acme', 'ACME');
    legacyKey('logs', 'billing-2', 'billing');

    [$code, $output] = runReseal(['--ring' => 'logs']);

    expect($code)->toBe(0)
        ->and($output)->toContain('logs:billing-2 → "billing"')->toContain('Re-sealed 1 key(s), 0 already bound.')->not->toContain('http:acme')
        ->and(storedFormats())->toBe(['http:acme' => 'sentinel.key/1', 'logs:billing-2' => 'sentinel.key/2']);
});

it('refuses a ring that is unknown or stores no keys in the database', function (string $ring, string $message): void {
    legacyKey('http', 'acme', 'ACME');

    [$code, $output] = runReseal(['--ring' => $ring]);

    expect($code)->toBe(1)
        ->and($output)->toContain($message)
        ->and(storedFormats())->toBe(['http:acme' => 'sentinel.key/1']);
})->with([
    'a config-only ring' => ['default', 'has no database driver'],
    'an unknown ring' => ['nope', 'not configured'],
]);

it('passes over config-only rings and reports an empty table', function (): void {
    [$code, $output] = runReseal();

    expect($code)->toBe(0)->and($output)->toContain('Re-sealed 0 key(s), 0 already bound.');
});

it('never re-seals a legacy key whose label is not UTF-8, and exits 1 (only SQLite stores one)', function (): void {
    Event::fake([KeyIntegrityViolated::class]);
    legacyKey('http', 'good', 'ACME');

    if (! corrupt(static fn () => legacyKey('http', 'binary', "caf\xE9"))) {
        return;
    }

    $binary = keyRow('http', 'binary');

    [$code, $output] = runReseal();

    expect($code)->toBe(1)
        ->and($output)->toMatch('/http:good → "ACME" \.+ binding/u')
        ->toMatch('/http:binary → "caf\x{FFFD}" \.+ label is not valid UTF-8 — not re-sealed/u')
        ->toContain('Re-sealed 1 key(s), 0 already bound.')
        ->toContain('1 legacy key(s) have a label that is not valid UTF-8, which cannot be bound. Correct the label, then run sentinel:key:reseal again.')
        ->not->toContain('Check the labels above')
        ->and(keyRow('http', 'binary'))->toBe($binary)
        ->and(storedFormats())->toBe(['http:good' => 'sentinel.key/2', 'http:binary' => 'sentinel.key/1']);

    Event::assertNotDispatched(KeyIntegrityViolated::class);
});

it('prints a key id a database writer planted escaped, never as terminal control sequences', function (): void {
    DB::table('sentinel_keys')->insert([
        'ring' => 'http', 'kid' => "x\e[2J<error>", 'algorithm' => 'hmac-sha256', 'status' => 'active',
        'activates_at' => '2026-10-01 00:00:00.000000', 'envelope' => 'sentinel:aes-256-gcm:planted',
    ]);

    [$code, $output] = runReseal();

    expect($code)->toBe(1)
        ->and($output)->toMatch('/http:"x\\\\u001b\[2J\\\\u003Cerror\\\\u003E"[ .]+fails its integrity check — not re-sealed/u')
        ->not->toContain("\e");
});

it('prints a hostile label escaped, never as terminal control sequences', function (): void {
    legacyKey('http', 'hostile', "Evil\e[2J\u{202E}gnp.exe\u{0085}\u{200B}<error>x</error>");

    [$code, $output] = runReseal(['--dry-run' => true]);

    expect($code)->toBe(0)
        ->and($output)->toContain('http:hostile → "Evil\u001b[2J\u202egnp.exe\u0085\u200b\u003Cerror\u003Ex\u003C/error\u003E"')
        ->not->toContain("\e")->not->toContain("\u{202E}")->not->toContain("\u{0085}")->not->toContain("\u{200B}");
});
