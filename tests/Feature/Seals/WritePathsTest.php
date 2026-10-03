<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Engine\LedgerWriter;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\TamperedWritePolicy;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\ModelSealed;
use RoundlyConsulting\Sentinel\Events\SealRemoved;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\CanonicalizationException;
use RoundlyConsulting\Sentinel\Exceptions\ConcurrentSealException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Sentinel\Tests\TestCase;

function versions(Model $model, string $seal = 'financial'): array
{
    return LedgerEntry::query()->where('sealable_id', $model->getKey())->where('sealable_type', $model->getMorphClass())
        ->where('seal', $seal)->orderBy('version')->pluck('version')->all();
}

/**
 * §10 item 18: every Eloquent write path seals atomically.
 */
it('seals every Eloquent write path', function (Closure $write, int $expectedVersion): void {
    $invoice = invoice(['amount' => '1.00']);

    $write($invoice);

    $fresh = Invoice::withTrashed()->findOrFail($invoice->id);

    expect(Sentinel::verify($fresh)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($fresh)->version)->toBe($expectedVersion)
        ->and(versions($fresh))->toBe(range(1, $expectedVersion));
})->with([
    'save' => [function (Invoice $i): void {
        $i->amount = '2.00';
        $i->save();
    }, 2],
    'saveQuietly' => [function (Invoice $i): void {
        $i->amount = '2.00';
        $i->saveQuietly();
    }, 2],
    'update' => [fn (Invoice $i) => $i->update(['status' => 'void']), 2],
    'updateQuietly' => [fn (Invoice $i) => $i->updateQuietly(['status' => 'void']), 2],
    'touch (computed seal re-seals on every update)' => [fn (Invoice $i) => $i->touch(), 2],
    'push' => [function (Invoice $i): void {
        $i->amount = '3.00';
        $i->push();
    }, 2],
    'increment' => [fn (Invoice $i) => $i->increment('customer_id'), 2],
    'decrement' => [fn (Invoice $i) => $i->decrement('customer_id', 2), 2],
    'incrementQuietly' => [fn (Invoice $i) => $i->incrementQuietly('customer_id'), 2],
    'updateOrCreate (existing)' => [fn (Invoice $i) => Invoice::query()->updateOrCreate(['id' => $i->id], ['status' => 'void']), 2],
    'soft delete (updated_at is not sealed, lines are)' => [fn (Invoice $i) => $i->delete(), 2],
    'restore' => [function (Invoice $i): void {
        $i->delete();
        $i->restore();
    }, 3],
    'no change at all' => [fn (Invoice $i) => $i->save(), 2],
]);

it('seals incrementEach and decrementEach (Laravel 13+)', function (): void {
    $invoice = invoice(['customer_id' => 5]);

    $invoice->incrementEach(['customer_id' => 2]);
    $invoice->decrementEach(['customer_id' => 1]);

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact)
        ->and(Sentinel::verify($invoice)->version)->toBe(3)
        ->and((int) DB::table('invoices')->value('customer_id'))->toBe(6);
})->skip(fn (): bool => ! method_exists(Model::class, 'incrementEach'), 'incrementEach() needs Laravel 13');

it('documents why incrementEach is Laravel 13+ only: on 12 it updates the whole table, unsealed (dual-review O-43)', function (): void {
    $mine = invoice(['customer_id' => 5]);
    $other = invoice(['customer_id' => 7]);

    // Laravel 12's Model has no incrementEach(): __call forwards it to a fresh query builder.
    $mine->incrementEach(['customer_id' => 2]);

    expect(DB::table('invoices')->orderBy('id')->pluck('customer_id')->map(static fn (mixed $id): int => (int) $id)->all())->toBe([7, 9])
        ->and(Sentinel::verify($other)->status)->toBe(VerificationStatus::Tampered);
})->skip(fn (): bool => method_exists(Model::class, 'incrementEach'), 'pins the Laravel 12 behaviour the README warns about');

it('seals created models through every create path', function (Closure $create): void {
    $invoice = $create();

    expect(Sentinel::verifyAll($invoice)->allIntact())->toBeTrue()
        ->and(versions($invoice))->toBe([1])
        ->and(versions($invoice, 'identity'))->toBe([1]);
})->with([
    'create' => [fn () => Invoice::query()->create(['number' => 'C-1'])],
    'firstOrCreate' => [fn () => Invoice::query()->firstOrCreate(['number' => 'C-2'])],
    'updateOrCreate (new)' => [fn () => Invoice::query()->updateOrCreate(['number' => 'C-3'], ['amount' => '4.00'])],
    'new + save' => [function (): Invoice {
        $invoice = new Invoice(['number' => 'C-4']);
        $invoice->save();

        return $invoice;
    }],
]);

it('re-seals only when a sealed column changes, except for computed seals', function (): void {
    $record = record();
    $record->update(['code' => 'A1']);
    $record->save();

    expect(versions($record, 'default'))->toBe([1]);

    $record->update(['name' => 'beta']);

    expect(versions($record, 'default'))->toBe([1, 2]);
});

it('covers database defaults and triggers through the read-back (§10 item 20)', function (): void {
    $invoice = Invoice::query()->create(['number' => 'D-1']);

    expect($invoice->getAttributes())->not->toHaveKey('region')
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);

    DB::table('invoices')->where('id', $invoice->id)->update(['region' => 'us']);

    expect(Sentinel::verify($invoice)->changedAttributes)->toBe(['a:region']);
});

it('dispatches ModelSealed after commit only', function (): void {
    Event::fake([ModelSealed::class]);

    DB::transaction(function (): void {
        invoice();
        Event::assertNotDispatched(ModelSealed::class);
    });

    Event::assertDispatched(ModelSealed::class, 2);
    Event::assertDispatched(ModelSealed::class, static fn (ModelSealed $event): bool => $event->seal === 'financial' && $event->event === SealEvent::Sealed && $event->version === 1);
});

/**
 * §10 item 19: a sealing failure rolls the model write back; an outer transaction survives a
 * caught failure (savepoint).
 */
it('rolls the write back when there is no signing key', function (): void {
    $invoice = invoice(['amount' => '1.00']);
    // The key can still verify (verify-only), so the pre-write check passes; signing cannot.
    config()->set('sentinel.keys.rings.default.previous', TestCase::ROOT_KEY_ID.'|hmac-sha256|'.TestCase::ROOT_KEY);
    config()->set('sentinel.keys.rings.default.key_id', null);
    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    expect(fn () => $invoice->update(['amount' => '2.00']))->toThrow(NoSigningKeyException::class)
        ->and((float) DB::table('invoices')->where('id', $invoice->id)->value('amount'))->toBe(1.0)
        ->and(versions($invoice))->toBe([1]);
});

it('rolls the write back when a stored value does not canonicalize', function (): void {
    $class = definedBy(static function ($seals): void {
        $seals->seal('typed')->attributes('number')->boolean('note');
    });
    $model = $class::query()->create(['number' => 'a', 'note' => '1']);

    // Something in the database (a trigger, a default) rewrites the row after the host's write.
    $class::updated(static fn (Model $updated) => DB::table('invoices')->where('id', $updated->getKey())->update(['note' => 'maybe']));

    expect(fn () => $model->update(['number' => 'b']))->toThrow(CanonicalizationException::class, 'not_boolean')
        ->and(DB::table('invoices')->where('id', $model->getKey())->value('number'))->toBe('a');
});

it('rolls the write back when it loses a version race', function (): void {
    $invoice = invoice(['amount' => '1.00']);

    // Another writer bumps the seal row between our read and our compare-and-swap.
    LedgerEntry::created(static fn () => Seal::query()->toBase()->increment('version', 100));

    expect(fn () => $invoice->update(['amount' => '2.00']))->toThrow(ConcurrentSealException::class)
        ->and((float) DB::table('invoices')->where('id', $invoice->id)->value('amount'))->toBe(1.0)
        ->and(versions($invoice))->toBe([1]);
});

it('turns a duplicate ledger version into ConcurrentSealException', function (): void {
    $invoice = invoice();
    $writer = app(LedgerWriter::class);
    $key = app(KeyStoreManager::class)->signingKey('default');

    expect(fn () => $writer->append($invoice, 'financial', $key, SealEvent::Resealed, 1, null, null, null, null, null, null, Clock::now()))
        ->toThrow(ConcurrentSealException::class);
});

it('turns a duplicate seal row into ConcurrentSealException', function (): void {
    config()->set('sentinel.ledger.enabled', false);
    $invoice = invoice();

    // The seal row vanishes from our view, so the engine inserts — and hits the unique index.
    Seal::addGlobalScope('hide', static fn ($query) => $query->whereRaw('1 = 0'));

    expect(fn () => Sentinel::for($invoice, 'identity')->seal())->toThrow(ConcurrentSealException::class);
});

it('keeps the outer transaction when a sealed write fails inside it', function (): void {
    $invoice = invoice();
    $other = invoice();
    DB::table('invoices')->where('id', $other->id)->update(['amount' => '0.00']);

    DB::transaction(function () use ($invoice, $other): void {
        $invoice->update(['amount' => '5.00']);

        try {
            $other->update(['note' => 'x']);
        } catch (TamperedModelException) {
        }
    });

    expect((float) DB::table('invoices')->where('id', $invoice->id)->value('amount'))->toBe(5.0)
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact)
        ->and(DB::table('invoices')->where('id', $other->id)->value('note'))->toBeNull();
});

/**
 * §10 item 12: the tampered-write policy.
 */
it('refuses writes to a tampered model and changes nothing (policy refuse)', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);
    $seal = Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->value('mac');

    try {
        $invoice->update(['note' => 'x']);
        $this->fail('expected TamperedModelException');
    } catch (TamperedModelException $exception) {
        expect($exception->result()?->status)->toBe(VerificationStatus::Tampered)
            ->and($exception->results())->toHaveCount(1);
    }

    expect(DB::table('invoices')->where('id', $invoice->id)->value('note'))->toBeNull()
        ->and(Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->value('mac'))->toBe($seal)
        ->and(versions($invoice))->toBe([1]);
});

it('writes and re-seals a tampered model, auditing the previous status (policy reseal)', function (): void {
    Event::fake([TamperDetected::class]);
    config()->set('sentinel.sealing.on_tampered_write', 'reseal');
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

    $invoice->update(['note' => 'x']);

    $entry = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->orderByDesc('version')->firstOrFail();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact)
        ->and($entry->previous_status)->toBe('tampered')
        ->and($entry->event)->toBe(SealEvent::Resealed);

    Event::assertDispatched(TamperDetected::class);
});

it('writes and leaves the seal as it was (policy skip, per seal)', function (): void {
    $class = definedBy(static function ($seals): void {
        $seals->seal('skipping')->attributes('number')->onTamperedWrite(TamperedWritePolicy::Skip);
    });
    $model = $class::query()->create(['number' => 'a']);
    DB::table('invoices')->where('id', $model->getKey())->update(['number' => 'b']);

    $model->update(['note' => 'x']);

    expect(DB::table('invoices')->where('id', $model->getKey())->value('note'))->toBe('x')
        ->and(Sentinel::verify($model)->status)->toBe(VerificationStatus::Tampered);
});

it('re-seals computed-only drift on a save, and records it', function (): void {
    $invoice = invoice();
    $invoice->lines()->create(['sku' => 'A', 'quantity' => 1]);

    expect(Sentinel::verify($invoice)->changedAttributes)->toBe(['c:lines']);

    $invoice->update(['note' => 'touched']);

    $entry = LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->orderByDesc('version')->firstOrFail();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact)
        ->and($entry->previous_status)->toBe('tampered');
});

it('refuses writes to a strict model that was never sealed until it is baselined', function (): void {
    Invoice::query()->insert(['number' => 'legacy']);
    $legacy = Invoice::query()->where('number', 'legacy')->firstOrFail();

    expect(fn () => $legacy->update(['note' => 'x']))->toThrow(TamperedModelException::class, 'never_sealed');

    Sentinel::seal($legacy);
    $legacy->update(['note' => 'x']);

    expect(Sentinel::verify($legacy)->status)->toBe(VerificationStatus::Intact);
});

/**
 * §10 item 21: deletes.
 */
it('keeps the seal on a soft delete and tombstones a force delete', function (): void {
    Event::fake([SealRemoved::class]);
    $invoice = invoice();

    $invoice->delete();

    expect(Seal::query()->where('sealable_id', $invoice->id)->count())->toBe(2)
        ->and(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Intact);

    $invoice->forceDelete();

    expect(Seal::query()->where('sealable_id', $invoice->id)->count())->toBe(0)
        ->and(LedgerEntry::query()->where('sealable_id', $invoice->id)->where('event', 'deleted')->count())->toBe(2);

    Event::assertDispatched(SealRemoved::class, static fn (SealRemoved $event): bool => $event->event === SealEvent::Deleted && $event->previousStatus === VerificationStatus::Intact);
});

it('tombstones a hard delete with the status the model had', function (): void {
    $record = record();
    DB::table('plain_records')->where('id', $record->id)->update(['name' => 'evil']);

    $record->delete();

    $entry = LedgerEntry::query()->where('sealable_id', $record->id)->orderByDesc('version')->firstOrFail();

    expect($entry->event)->toBe(SealEvent::Deleted)
        ->and($entry->previous_status)->toBe('tampered')
        ->and($entry->seal_mac)->toBeNull();
});

it('does not re-seal a tampered model on a soft delete', function (): void {
    $invoice = invoice();
    $invoice->lines()->create(['sku' => 'A', 'quantity' => 1]);
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);

    $invoice->delete();

    expect(Sentinel::verify($invoice)->status)->toBe(VerificationStatus::Tampered);
});

it('treats a re-used id after an out-of-band delete as stale (entity_recreated)', function (string $policy, bool $created): void {
    config()->set('sentinel.sealing.on_tampered_write', $policy);
    $record = record();
    DB::table('plain_records')->where('id', $record->id)->delete();

    $attempt = fn () => PlainRecord::query()->create(['id' => $record->id, 'name' => 'reused']);

    if (! $created) {
        expect($attempt)->toThrow(TamperedModelException::class, 'entity_recreated');

        return;
    }

    $attempt();

    expect(DB::table('plain_records')->where('id', $record->id)->exists())->toBeTrue();
})->with([
    'refuse' => ['refuse', false],
    'reseal' => ['reseal', true],
    'skip' => ['skip', true],
]);

it('seals nothing and refuses no write when auto-sealing is off (verify-only nodes)', function (): void {
    config()->set('sentinel.sealing.auto', 'off');
    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    $invoice = invoice();

    expect(Seal::query()->count())->toBe(0)
        ->and(fn () => Sentinel::seal($invoice))->toThrow(NoSigningKeyException::class);
});
