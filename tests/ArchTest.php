<?php

declare(strict_types=1);

use GuzzleHttp\Psr7\HttpFactory;
use RoundlyConsulting\Sentinel\Canonical\FieldTagger;
use RoundlyConsulting\Sentinel\Http\Signatures\MessageSigner;
use RoundlyConsulting\Sentinel\Keys\Hkdf;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Tests\Support\SourceScan;
use RoundlyConsulting\Testing\Arch\ArchPresets;

/**
 * The arch presets this package's shape qualifies for, plus the bespoke pins of plan §12.1.
 *
 * Not adopted, because they would be vacuous: `swappableModelsAreNotFinal` and
 * `modelsResolveThroughSeam` — Sentinel's models are deliberately not swappable (D26).
 * `modelsGoThroughTheFacade` guards the HasSeals trait and the package models.
 */
ArchPresets::strictTypes('RoundlyConsulting\Sentinel');
// The manager is the one deliberate non-final class: SentinelFake extends it, so an injected
// manager still type-checks under Sentinel::fake().
ArchPresets::finalByDefault('RoundlyConsulting\Sentinel', [SentinelManager::class]);
// No exemptions: every primitive goes through crypto-for-laravel (hash_hkdf is not on the
// list — it is pinned to Keys\Hkdf below instead).
ArchPresets::noLocalCryptoPrimitives('RoundlyConsulting\Sentinel');
ArchPresets::morphColumnsUseTheSeam(__DIR__.'/../database/migrations');
ArchPresets::runtimeRequireIsWhitelisted(__DIR__.'/../composer.json');
ArchPresets::noDebuggingLeftovers();
ArchPresets::modelsGoThroughTheFacade('RoundlyConsulting\Sentinel');

/**
 * @param  Closure(string $class, string $file): void  $check
 */
function eachSourceClass(Closure $check): int
{
    $classes = SourceScan::classes();

    expect($classes)->not->toBeEmpty();

    foreach ($classes as $class => $file) {
        $check($class, $file);
    }

    return count($classes);
}

it('(a) calls hash_hkdf only from Keys\Hkdf', function (): void {
    $calls = [];

    eachSourceClass(function (string $class, string $file) use (&$calls): void {
        $count = SourceScan::functionCalls($file, 'hash_hkdf');

        if ($count > 0) {
            $calls[$class] = $count;
        }
    });

    expect($calls)->toBe([Hkdf::class => 1]);
});

it('(b) reads the time only through Support\Clock', function (): void {
    $offenders = [];
    $clockReads = 0;

    eachSourceClass(function (string $class, string $file) use (&$offenders, &$clockReads): void {
        $reads = SourceScan::functionCalls($file, 'now') + SourceScan::functionCalls($file, 'time')
            + SourceScan::functionCalls($file, 'microtime') + SourceScan::functionCalls($file, 'date')
            + SourceScan::staticCalls($file, ['Date', 'Carbon', 'CarbonImmutable', 'Facades\\Date'], 'now');

        if ($class === Clock::class) {
            $clockReads = $reads;
        } elseif ($reads > 0) {
            $offenders[] = $class;
        }
    });

    expect($clockReads)->toBe(1)->and($offenders)->toBe([]);
});

it('(c) declares no static properties anywhere (Octane-safe)', function (): void {
    $offenders = [];

    $scanned = eachSourceClass(function (string $class) use (&$offenders): void {
        if (! class_exists($class) && ! trait_exists($class) && ! interface_exists($class) && ! enum_exists($class)) {
            return;
        }

        foreach ((new ReflectionClass($class))->getProperties(ReflectionProperty::IS_STATIC) as $property) {
            if ($property->getDeclaringClass()->getName() === $class) {
                $offenders[] = $class.'::$'.$property->getName();
            }
        }
    });

    expect($scanned)->toBeGreaterThan(20)->and($offenders)->toBe([]);
});

it('(d) imports neither the DB facade nor Illuminate\Foundation', function (): void {
    $offenders = [];

    eachSourceClass(function (string $class, string $file) use (&$offenders): void {
        foreach (SourceScan::imports($file) as $import) {
            if ($import === 'Illuminate\Support\Facades\DB' || str_starts_with($import, 'Illuminate\Foundation\\')) {
                $offenders[] = "{$class} imports {$import}";
            }
        }
    });

    expect($offenders)->toBe([]);
});

it('(e) keeps Canonical free of Illuminate\Database', function (): void {
    $canonical = 0;
    $offenders = [];

    eachSourceClass(function (string $class, string $file) use (&$canonical, &$offenders): void {
        if (! str_starts_with($class, 'RoundlyConsulting\Sentinel\Canonical\\') && ! str_starts_with($class, 'RoundlyConsulting\Sentinel\Http\StructuredFields\\')) {
            return;
        }

        $canonical++;

        foreach (SourceScan::imports($file) as $import) {
            if (str_starts_with($import, 'Illuminate\Database\\')) {
                $offenders[] = "{$class} imports {$import}";
            }
        }
    });

    expect($canonical)->toBeGreaterThan(5)->and($offenders)->toBe([]);
});

it('(f) marks every Canonical, Keys, Engine and Ledger class @internal', function (): void {
    // The custom key-store extension surface stays public: a driver builds SealingKeys from
    // KeyMaterial.
    $public = [SealingKey::class, KeyMaterial::class];
    $checked = 0;
    $offenders = [];

    eachSourceClass(function (string $class) use ($public, &$checked, &$offenders): void {
        if (preg_match('/^RoundlyConsulting\\\\Sentinel\\\\(Canonical|Keys|Engine|Ledger)\\\\/', $class) !== 1 || in_array($class, $public, true)) {
            return;
        }

        $checked++;

        if (! str_contains((string) (new ReflectionClass($class))->getDocComment(), '@internal')) {
            $offenders[] = $class;
        }
    });

    expect($checked)->toBeGreaterThan(10)->and($offenders)->toBe([]);
});

it('(g) touches crypto Hmac, Hs, EdDSA and Es only from FieldTagger and Signers', function (): void {
    // KeyMaterial no longer probes Ed25519 keys: crypto >= 1.0.1 refuses a secret key whose
    // public half does not match its seed.
    $allowed = [FieldTagger::class, Signers::class];
    $primitives = ['RoundlyConsulting\Crypto\Hash\Hmac', 'RoundlyConsulting\Crypto\Signature\Hs', 'RoundlyConsulting\Crypto\Signature\EdDSA', 'RoundlyConsulting\Crypto\Signature\Es'];
    $users = [];

    eachSourceClass(function (string $class, string $file) use ($primitives, &$users): void {
        if (array_intersect(SourceScan::imports($file), $primitives) !== []) {
            $users[] = $class;
        }
    });

    sort($users);
    sort($allowed);

    expect($users)->toBe($allowed);
});

it('(h) never calls hash_equals (ConstantTime::equals instead)', function (): void {
    $offenders = [];

    eachSourceClass(function (string $class, string $file) use (&$offenders): void {
        if (SourceScan::functionCalls($file, 'hash_equals') > 0) {
            $offenders[] = $class;
        }
    });

    expect($offenders)->toBe([]);
});

it('(i) passes JSON_THROW_ON_ERROR to every json_decode', function (): void {
    $calls = 0;
    $offenders = [];

    eachSourceClass(function (string $class, string $file) use (&$calls, &$offenders): void {
        foreach (SourceScan::callArguments($file, 'json_decode') as $arguments) {
            $calls++;

            if (! str_contains($arguments, 'JSON_THROW_ON_ERROR')) {
                $offenders[] = $class;
            }
        }
    });

    expect($calls)->toBeGreaterThan(0)->and($offenders)->toBe([]);
});

/**
 * Outbound body buffering builds its stream with `GuzzleHttp\Psr7\HttpFactory`. That is not a
 * runtime require of its own: `guzzlehttp/psr7` arrives with `illuminate/http` (the HTTP client
 * Laravel ships), so the class is present exactly as long as `illuminate/http` stays required.
 */
it('(j) reaches Guzzle PSR-7 only through illuminate/http, from the outbound signer only (dual-review O-22)', function (): void {
    $require = json_decode((string) file_get_contents(__DIR__.'/../composer.json'), true, flags: JSON_THROW_ON_ERROR)['require'];
    $users = [];

    eachSourceClass(function (string $class, string $file) use (&$users): void {
        foreach (SourceScan::imports($file) as $import) {
            if (str_starts_with($import, 'GuzzleHttp\\')) {
                $users[] = "{$class} imports {$import}";
            }
        }
    });

    expect($require)->toHaveKey('illuminate/http')
        ->not->toHaveKey('guzzlehttp/psr7')
        ->not->toHaveKey('guzzlehttp/guzzle')
        ->and(class_exists(HttpFactory::class))->toBeTrue()
        ->and($users)->toBe([MessageSigner::class.' imports '.HttpFactory::class]);
});
