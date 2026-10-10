<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * §10 items 1–5: out-of-band writes are detected on the next verification, with the changed
 * attribute names — never values.
 */
it('detects a query-builder write and names the changed column (§10 item 1)', function (): void {
    Event::fake([TamperDetected::class]);
    $invoice = invoice();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);

    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);
    $result = Sentinel::verify($invoice);

    expect($result->status)->toBe(VerificationStatus::Tampered)
        ->and($result->reason)->toBe('mac')
        ->and($result->changedAttributes)->toBe(['a:amount'])
        ->and($result->isIntact())->toBeFalse()
        ->and($result->toArray())->toMatchArray(['status' => 'tampered', 'changed_attributes' => ['a:amount'], 'intact' => false])
        ->and(json_encode($result->toArray()))->not->toContain('"0.00"')
        ->and(fn () => Sentinel::verifyOrFail($invoice))->toThrow(TamperedModelException::class, 'tampered: mac');

    Event::assertDispatched(TamperDetected::class, static fn (TamperDetected $event): bool => $event->changedAttributes === ['a:amount'] && $event->context === VerificationContext::Api);
});

it('detects every bypass of Eloquent (§10 item 2)', function (): void {
    $updated = invoice();
    $upserted = invoice();

    Invoice::query()->whereKey($updated->id)->update(['currency' => 'USD']);
    Invoice::query()->upsert([['id' => $upserted->id, 'customer_id' => 99]], ['id'], ['customer_id']);
    Invoice::query()->insert(['customer_id' => 1, 'amount' => '1.00', 'status' => 'draft']);
    $inserted = Invoice::query()->latest('id')->firstOrFail();

    expect(Sentinel::verify($updated)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::verify($updated)->changedAttributes)->toBe(['a:currency'])
        ->and(Sentinel::verify($upserted)->changedAttributes)->toBe(['a:customer_id'])
        ->and(Sentinel::verify($inserted)->status)->toBe(VerificationStatus::Missing)
        ->and(Sentinel::verify($inserted)->reason)->toBe('never_sealed')
        ->and(Sentinel::verify($inserted, 'identity')->status)->toBe(VerificationStatus::Unsealed)
        ->and(Sentinel::isIntact($inserted))->toBeFalse()
        ->and($inserted->isIntact())->toBeFalse();
});

it('refuses values and seals copied to another row, seal, scope or app (§10 item 3)', function (Closure $paste): void {
    $source = invoice(['amount' => '99.00']);
    $target = invoice(['amount' => '1.00']);

    $paste($source, $target);

    expect(Sentinel::verify($target)->status)->toBe(VerificationStatus::Tampered);
})->with([
    'another row of the same model' => [function (Invoice $source, Invoice $target): void {
        DB::table('invoices')->where('id', $target->id)->update(['amount' => '99.00']);
        $seal = Seal::query()->where('sealable_id', $source->id)->where('seal', 'financial')->firstOrFail();
        Seal::query()->where('sealable_id', $target->id)->where('seal', 'financial')
            ->update($seal->only(['mac', 'version', 'previous_digest', 'field_tags', 'sealed_at', 'key_id']));
    }],
    'another tenant scope' => [function (Invoice $source, Invoice $target): void {
        DB::table('invoices')->where('id', $target->id)->update(['tenant_id' => 2]);
    }],
    'another app context' => [function (Invoice $source, Invoice $target): void {
        config()->set('sentinel.context', 'other-app');
    }],
]);

it('refuses a seal row moved to another model or seal name (§10 items 3–4)', function (): void {
    $invoice = invoice();
    $record = record();
    $financial = Seal::query()->where('sealable_type', $invoice->getMorphClass())->where('seal', 'financial');

    // Re-point the financial seal at the identity seal name.
    Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'identity')->delete();
    (clone $financial)->update(['seal' => 'identity']);

    expect(Sentinel::verify($invoice, 'identity')->status)->not->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Missing);

    // Re-point the record's seal at another record.
    $other = record(['name' => 'alpha', 'count' => 3, 'code' => 'A1']);
    Seal::query()->where('sealable_id', $other->id)->where('sealable_type', $record->getMorphClass())->delete();
    Seal::query()->where('sealable_id', $record->id)->where('sealable_type', $record->getMorphClass())->update(['sealable_id' => $other->id]);

    expect(Sentinel::verify($other)->status)->toBe(VerificationStatus::Tampered);
});

it('reports a deleted seal row as missing, even on a lenient seal (§10 item 5)', function (): void {
    $invoice = invoice();
    Seal::query()->where('sealable_id', $invoice->id)->delete();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Missing)
        ->and(Sentinel::verify($invoice)->reason)->toBe('seal_deleted')
        ->and(Sentinel::verify($invoice, 'identity')->reason)->toBe('seal_deleted')
        ->and(Sentinel::verify($invoice)->ledgerVersion)->toBe(1);
});

it('cannot tell a deleted seal from a never-sealed row without the ledger', function (): void {
    config()->set('sentinel.ledger.enabled', false);
    $invoice = invoice();
    Seal::query()->where('sealable_id', $invoice->id)->delete();

    expect(Sentinel::verify($invoice)->reason)->toBe('never_sealed')
        ->and(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Unsealed);
});

it('pins the algorithm to the key, never to the stored row (§10 item 8)', function (): void {
    $invoice = invoice();
    Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->update(['algorithm' => 'hmac-sha512']);

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::AlgorithmMismatch);

    $other = invoice();
    config()->set('sentinel.keys.rings.default.algorithms', ['ed25519']);

    expect(Sentinel::verify($other)->status)->toBe(VerificationStatus::AlgorithmNotAllowed)
        ->and(Sentinel::verify($other)->algorithm)->toBe(Algorithm::HmacSha256);
});

it('detects stored values that no longer canonicalize', function (): void {
    $class = definedBy(static function ($seals): void {
        $seals->seal('typed')->attributes('number')->boolean('note');
    });
    $model = $class::query()->create(['number' => 'n', 'note' => '1']);
    DB::table('invoices')->where('id', $model->getKey())->update(['note' => 'maybe']);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::verify($model)->reason)->toBe('canonicalization');
});

/**
 * Chat review C-5: Laravel's boolean cast is `(bool) $value`, so 'false' and 'f' read as true.
 */
it('never takes a false-looking string for a sealed false', function (string $written): void {
    $class = definedBy(static function ($seals): void {
        $seals->seal('typed')->attributes('number')->boolean('note');
    });
    $model = $class::query()->create(['number' => 'n', 'note' => '0']);
    DB::table('invoices')->where('id', $model->getKey())->update(['note' => $written]);

    expect(Sentinel::verify($model)->status)->toBe(VerificationStatus::Tampered)
        ->and(Sentinel::verify($model)->reason)->toBe('canonicalization');
})->with(['false', 'f', 'FALSE', 'F']);

it('detects a sealed boolean flipped to a string the cast reads as true', function (string $written): void {
    $invoice = invoice(['paid' => false]);
    DB::table('invoices')->where('id', $invoice->id)->update(['paid' => $written]);

    expect(Invoice::query()->findOrFail($invoice->id)->paid)->toBeTrue()
        ->and(Sentinel::verify($invoice)->status)->not->toBe(VerificationStatus::Intact);
})->with(['false', 'f', 'FALSE'])
    ->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'only SQLite keeps text in a boolean column (pgsql parses it, strict MySQL refuses it)');

it('detects an encrypted column that no longer decrypts', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['secret' => 'not-a-ciphertext']);

    expect(Sentinel::verify($invoice, 'identity')->reason)->toBe('canonicalization');
});

it('seals the decrypted plaintext of an encrypted column', function (): void {
    $invoice = invoice(['secret' => 'iban-1']);
    $reencrypted = encrypt('iban-1', false);
    DB::table('invoices')->where('id', $invoice->id)->update(['secret' => $reencrypted]);

    // A different ciphertext of the same plaintext is still intact.
    expect(Sentinel::verify($invoice, 'identity')->status)->toBe(VerificationStatus::Intact);

    DB::table('invoices')->where('id', $invoice->id)->update(['secret' => encrypt('iban-2', false)]);

    expect(Sentinel::verify($invoice, 'identity')->changedAttributes)->toBe(['a:secret']);
});

it('reports a sealed row that vanished, and attribute columns missing from it', function (): void {
    $record = record();
    DB::table('plain_records')->where('id', $record->id)->delete();

    expect(Sentinel::verify($record)->status)->toBe(VerificationStatus::Unverifiable)
        ->and(Sentinel::verify($record)->reason)->toBe('missing_attribute');
});

it('stays intact for nulls and outdated definitions', function (): void {
    $record = record(['name' => null, 'count' => null, 'code' => null, 'flag' => null, 'ratio' => null]);

    expect(Sentinel::verify($record)->status)->toBe(VerificationStatus::Intact);

    Seal::query()->where('sealable_id', $record->id)->update(['manifest' => json_encode([
        ['a:code', 'auto'], ['a:count', 'auto'], ['a:flag', 'bool'], ['a:name', 'auto'], ['a:ratio', 'flt:3'],
    ])]);

    // The MAC no longer matches the edited manifest — but an outdated manifest alone is fine:
    $fresh = record();
    $seal = Seal::query()->where('sealable_id', $fresh->id)->firstOrFail();

    expect(Sentinel::verify($record)->status)->toBe(VerificationStatus::Tampered)
        ->and($seal->manifest)->toHaveCount(6);
});
