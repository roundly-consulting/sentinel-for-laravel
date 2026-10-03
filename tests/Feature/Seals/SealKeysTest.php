<?php

declare(strict_types=1);

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Stringable;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Definition\SealBuilder;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\InvoiceStatus;
use RoundlyConsulting\Sentinel\Tests\TestCase;

function useDatabaseDefaultRing(): void
{
    config()->set('sentinel.keys.rings.default.driver', 'chain');
    config()->set('sentinel.keys.rings.default.drivers', ['database', 'config']);
    app(KeyStoreManager::class)->flush();
}

it('reports revoked, retired, pending and unknown keys before any MAC (§10 item 10)', function (array $state, VerificationStatus $status, ?string $reason): void {
    useDatabaseDefaultRing();
    $key = Key::factory()->create(['kid' => 'db-key']);
    $invoice = invoice();

    expect(Sentinel::verify($invoice)->keyId)->toBe('db-key');

    Key::query()->whereKey($key->id)->delete();
    Key::factory()->create(['kid' => 'db-key', ...$state]);
    app(KeyStoreManager::class)->flush();

    $result = Sentinel::verify($invoice);

    expect($result->status)->toBe($status)->and($result->reason)->toBe($reason);
})->with([
    'revoked' => [['status' => 'revoked', 'revoked_at' => Carbon::now()], VerificationStatus::RevokedKey, null],
    'retired' => [['status' => 'retired'], VerificationStatus::RetiredKey, null],
    'pending' => [['activates_at' => Carbon::now()->addDay()], VerificationStatus::UnknownKey, 'pending'],
]);

it('reports unknown keys and keys whose envelope was tampered with', function (): void {
    useDatabaseDefaultRing();
    $key = Key::factory()->create(['kid' => 'db-key']);
    $invoice = invoice();

    Key::query()->whereKey($key->id)->update(['status' => 'verify_only']);
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::verify($invoice)->reason)->toBe('integrity');

    Key::query()->whereKey($key->id)->delete();
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::UnknownKey)
        ->and(Sentinel::verify($invoice)->reason)->toBe('not_found');
});

it('revokes config keys through the revocation list', function (): void {
    $invoice = invoice();
    config()->set('sentinel.keys.revoked', 'default:'.TestCase::ROOT_KEY_ID);
    app(KeyStoreManager::class)->flush();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::RevokedKey)
        // A write is refused before it ever needs the (revoked) signing key.
        ->and(fn () => $invoice->update(['note' => 'x']))->toThrow(TamperedModelException::class, 'revoked_key')
        ->and(fn () => invoice())->toThrow(NoSigningKeyException::class);
});

it('keeps old seals verifying through a rotation (§10 item 34)', function (): void {
    $before = invoice();
    $previous = TestCase::ROOT_KEY_ID.'|hmac-sha256|'.TestCase::ROOT_KEY;
    config()->set('sentinel.keys.rings.default.key_id', 'rotated');
    config()->set('sentinel.keys.rings.default.key', KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate());
    config()->set('sentinel.keys.rings.default.algorithm', 'ed25519');
    config()->set('sentinel.keys.rings.default.previous', $previous);
    app(KeyStoreManager::class)->flush();

    $after = invoice();

    expect(Sentinel::verify($before)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($before)->keyId)->toBe(TestCase::ROOT_KEY_ID)
        ->and(Sentinel::verify($after)->keyId)->toBe('rotated')
        ->and(Sentinel::verify($after)->algorithm)->toBe(Algorithm::Ed25519)
        ->and(Seal::query()->where('sealable_id', $after->id)->value('field_tags'))->toBeNull()
        ->and(Sentinel::currentSeal($after)?->algorithm)->toBe('ed25519');

    DB::table('invoices')->where('id', $after->id)->update(['amount' => '0.01']);

    // Asymmetric seals carry no field tags: what changed is unknown.
    expect(Sentinel::verify($after)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::verify($after)->changedAttributes)->toBeNull();
});

it('refuses to seal with a key the seal does not allow', function (): void {
    config()->set('sentinel.keys.rings.default.key', KeyMaterial::generate(Algorithm::Ed25519)->encodedPrivate());
    config()->set('sentinel.keys.rings.default.algorithm', 'ed25519');
    app(KeyStoreManager::class)->flush();

    $class = definedBy(static function (SealBuilder $seals): void {
        $seals->seal('hmac-only')->attributes('number')->algorithms(Algorithm::HmacSha256);
    });

    expect(fn () => $class::query()->create(['number' => 'x']))->toThrow(AlgorithmNotAllowedException::class, 'hmac-only')
        ->and($class::query()->count())->toBe(0);
});

it('never lets a kid of another ring, or another ring\'s secret, stand in for a seal key (§10 item 9)', function (): void {
    $invoice = invoice();
    Key::factory()->ring('http')->create(['kid' => TestCase::ROOT_KEY_ID]);
    Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->update(['ring' => 'http']);

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::UnknownKey)
        ->and(Sentinel::verify($invoice)->reason)->toBe('ring_not_accepted');

    // The same root secret in another ring yields a different subkey, so a MAC made with the
    // partner copy never verifies as a seal.
    $material = KeyMaterial::fromEncoded(Algorithm::HmacSha256, TestCase::ROOT_KEY);
    $seal = (new Signers)->sign(new SealingKey('default', 'k', $material), Purpose::Seal, 'document');
    $partner = (new Signers)->sign(new SealingKey('http', 'k', $material), Purpose::Seal, 'document');

    expect($seal)->not->toBe($partner);
});

it('accepts seals of an extra ring during a ring migration', function (): void {
    $define = static fn (?string $ring, array $accept): Closure => static function (SealBuilder $seals) use ($ring, $accept): void {
        $seal = $seals->seal('migrating')->attributes('number');

        if ($ring !== null) {
            $seal->ring($ring)->acceptRings(...$accept);
        }
    };

    archiveRing();
    $class = definedBy($define(null, []));
    $model = $class::query()->create(['number' => 'n']);

    // The seal moves to the archive ring; seals made in the default ring keep verifying only
    // while acceptRings() names it.
    $class::$define = $define('archive', ['default']);
    app()->forgetInstance(DefinitionRegistry::class);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($model)->ring)->toBe('default');

    $class::$define = $define('archive', []);
    app()->forgetInstance(DefinitionRegistry::class);

    expect(Sentinel::verify($model)->reason)->toBe('ring_not_accepted');
});

it('detects a replayed or rolled-back seal through the ledger (§10 item 6)', function (): void {
    $invoice = invoice(['amount' => '1.00']);
    $invoice->update(['amount' => '2.00']);
    $invoice->update(['amount' => '3.00']);

    $row = DB::table('invoices')->where('id', $invoice->id)->first();
    $seal = Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->firstOrFail()->getAttributes();

    $invoice->update(['amount' => '4.00']);
    $invoice->update(['amount' => '5.00']);

    // Restore the v3 row and its v3 seal row (a snapshot replay).
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => $row?->amount]);
    Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->update(collect($seal)->except(['id'])->all());

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Stale)
        ->and(Sentinel::verify($invoice)->reason)->toBe('newer_version')
        ->and(Sentinel::verify($invoice)->ledgerVersion)->toBe(5);

    // Deleting the newer entries inside the checkpoint window is undetectable from the
    // database alone (§3.2 #8) — checkpoints and anchors (Phase E) close it.
    LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->where('version', '>', 3)->toBase()->delete();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);

    // The seal row references its entry; the attacker must unlink it first.
    Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->toBase()->update(['ledger_entry_id' => null]);
    LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->where('version', 3)->toBase()->delete();

    expect(Sentinel::verify($invoice)->reason)->toBe('not_in_ledger');
});

it('detects a seal row and ledger entry that disagree, and a forged ledger entry', function (): void {
    $invoice = invoice();
    $entries = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial');

    (clone $entries)->toBase()->update(['seal_mac' => Base64Url::encode(random_bytes(32))]);

    expect(Sentinel::verify($invoice)->reason)->toBe('ledger_mismatch');

    $other = invoice();
    LedgerEntry::query()->where('sealable_id', $other->id)->where('seal', 'financial')->toBase()->update(['reason' => 'forged']);

    expect(Sentinel::verify($other)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::verify($other)->reason)->toBe('ledger_entry');

    config()->set('sentinel.verification.check_ledger', false);

    expect(Sentinel::verify($other)->status)->toBe(VerificationStatus::Intact);
});

it('reports malformed seal rows', function (array $columns, string $reason): void {
    $invoice = invoice();

    if (! corrupt(fn () => Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->toBase()->update($columns))) {
        return;
    }

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Malformed)
        ->and(Sentinel::verify($invoice)->reason)->toBe($reason);
})->with([
    'format' => [['format' => 2], 'format'],
    'manifest not JSON' => [['manifest' => '{'], 'manifest'],
    'manifest not pairs' => [['manifest' => '[["a:amount"]]'], 'manifest'],
    'manifest bad tag' => [['manifest' => '[["a:amount","money"]]'], 'manifest'],
    'manifest bad name' => [['manifest' => '[["x:amount","str"]]'], 'manifest'],
    'manifest empty' => [['manifest' => '[]'], 'manifest'],
    'mac' => [['mac' => 'not base64url!'], 'mac'],
    'version' => [['version' => 0], 'version'],
    'sealed_at' => [['sealed_at' => '2026-13-45 99:99:99'], 'sealed_at'],
]);

it('treats a changed definition over intact data as outdated (§4.6 row 19)', function (): void {
    $define = static fn (array $columns): Closure => static function (SealBuilder $seals) use ($columns): void {
        $seals->seal('evolving')->attributes(...$columns);
    };
    $class = definedBy($define(['number']));
    $model = $class::query()->create(['number' => 'n', 'currency' => 'EUR']);

    $class::$define = $define(['number', 'currency']);
    app()->forgetInstance(DefinitionRegistry::class);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Outdated)
        ->and(Sentinel::verify($model)->isIntact())->toBeTrue();

    config()->set('sentinel.verification.outdated_is_intact', false);

    expect(Sentinel::verify($model)->isIntact())->toBeFalse();

    // A save re-seals it under the new manifest, even with nothing else changing.
    $model->save();

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Intact);
});

it('reports a computed field no longer declared as unverifiable', function (): void {
    $define = static fn (bool $computed): Closure => static function (SealBuilder $seals) use ($computed): void {
        $seal = $seals->seal('computed')->attributes('number');

        if ($computed) {
            $seal->computed('upper', static fn ($model): string => strtoupper((string) $model->number));
        }
    };
    $class = definedBy($define(true));
    $model = $class::query()->create(['number' => 'n']);

    $class::$define = $define(false);
    app()->forgetInstance(DefinitionRegistry::class);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Unverifiable)
        ->and(Sentinel::verify($model)->reason)->toBe('missing_computed');
});

it('fails closed on every unreadable ledger entry column', function (array $columns): void {
    $invoice = invoice();

    if (! corrupt(fn () => LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->toBase()->update($columns))) {
        return;
    }

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::verify($invoice)->reason)->toBe('ledger_entry');
})->with([
    'event' => [['event' => 'bogus']],
    'previous status' => [['previous_status' => 'bogus']],
    'changed not JSON' => [['changed' => '{']],
    'changed not a list' => [['changed' => '{"a":1}']],
    'changed not names' => [['changed' => '[1]']],
    'occurred_at' => [['occurred_at' => '2026-13-45 99:99:99']],
    'entry mac encoding' => [['entry_mac' => 'not base64url!']],
    'entry key unknown' => [['key_id' => 'nope']],
]);

it('refuses a scope closure that returns something unbindable', function (): void {
    $class = definedBy(static function (SealBuilder $seals): void {
        $seals->seal('scoped')->attributes('number')->scope(static fn (): array => ['tenant' => 1]);
    });

    expect(fn () => $class::query()->create(['number' => 'n']))->toThrow(CanonicalizationException::class, 'scope');
});

it('binds int, enum and stringable scopes alike', function (mixed $scope): void {
    $class = definedBy(static function (SealBuilder $seals) use ($scope): void {
        $seals->seal('scoped')->attributes('number')->scope(static fn (): mixed => $scope);
    });

    expect(Sentinel::verify($class::query()->create(['number' => 'n']))->status)->toBe(VerificationStatus::Intact);
})->with([7, InvoiceStatus::Paid, new Stringable('t-1'), null]);
