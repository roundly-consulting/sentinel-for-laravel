<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Enums\Reaction;
use RoundlyConsulting\Sentinel\Enums\SealEvent;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Events\ModelSealed;
use RoundlyConsulting\Sentinel\Events\SealRemoved;
use RoundlyConsulting\Sentinel\Events\TamperAcknowledged;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

/**
 * I-15: listeners read changed columns by name and load the model behind an event.
 */
afterEach(function (): void {
    Relation::morphMap([], false);
});

it('strips the field tag prefixes', function (?array $changed, array $columns, array $computed): void {
    $result = new VerificationResult(VerificationStatus::Tampered, 'mac', Invoice::class, 1, 'financial', changedAttributes: $changed);
    $detected = new TamperDetected(Invoice::class, 1, 'financial', VerificationStatus::Tampered, 'mac', $changed, VerificationContext::Api, 'k');
    $acknowledged = new TamperAcknowledged(Invoice::class, 1, 'financial', 2, VerificationStatus::Tampered, $changed, 'INC-1', null, null);

    expect($result->changedColumns())->toBe($columns)
        ->and($result->changedComputed())->toBe($computed)
        ->and($detected->changedColumns())->toBe($columns)
        ->and($detected->changedComputed())->toBe($computed)
        ->and($acknowledged->changedColumns())->toBe($columns)
        ->and($acknowledged->changedComputed())->toBe($computed);
})->with([
    'mixed' => [['a:amount', 'c:lines', 'a:status'], ['amount', 'status'], ['lines']],
    'empty' => [[], [], []],
    'unknown' => [null, [], []],
]);

it('reads the changed columns of a real finding', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);
    Event::fake([TamperDetected::class]);

    expect(Sentinel::verify($invoice)->changedColumns())->toBe(['amount']);

    Event::assertDispatched(TamperDetected::class, static fn (TamperDetected $event): bool => $event->changedColumns() === ['amount'] && $event->changedComputed() === []);
});

it('loads the model behind every model event', function (): void {
    Event::fake([ModelSealed::class, TamperDetected::class, TamperAcknowledged::class, SealRemoved::class]);
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);
    Sentinel::verify($invoice);
    Sentinel::acknowledge($invoice, 'INC-3: reviewed');
    Sentinel::unseal($invoice, 'archived', seal: 'identity');

    foreach ([ModelSealed::class, TamperDetected::class, TamperAcknowledged::class, SealRemoved::class] as $class) {
        $event = Event::dispatched($class)->first()[0];

        expect($event->model()?->is($invoice))->toBeTrue("{$class}::model()");
    }
});

it('loads a tampered model guarded by a Throw retrieve seal', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('guarded')->attributes('number', 'amount')->verifyOnRetrieve(Reaction::Throw));
    $model = $class::query()->create(['number' => 'E-1', 'amount' => '5.00']);
    DB::table('invoices')->where('id', $model->getKey())->update(['amount' => '0.00']);
    $loaded = null;
    Event::listen(TamperDetected::class, static function (TamperDetected $event) use (&$loaded): void {
        $loaded = $event->model();
    });

    expect(fn () => $class::query()->find($model->getKey()))->toThrow(TamperedModelException::class)
        ->and($loaded?->getKey())->toBe($model->getKey());
});

it('resolves morph aliases, includes soft-deleted rows and returns null after a hard delete', function (): void {
    Relation::morphMap(['plain' => PlainRecord::class]);
    $record = record();
    $invoice = invoice();
    $invoice->delete();

    $plain = new ModelSealed('plain', $record->id, 'default', 1, 'k', SealEvent::Sealed);
    $trashed = new ModelSealed(Invoice::class, $invoice->id, 'financial', 1, 'k', SealEvent::Sealed);
    $gone = new SealRemoved('plain', 999, 'default', SealEvent::Deleted, null);
    $unknown = new SealRemoved('App\\Models\\Gone', 1, 'default', SealEvent::Deleted, null);

    expect($plain->model()?->is($record))->toBeTrue()
        ->and($trashed->model()?->is($invoice))->toBeTrue()
        ->and($gone->model())->toBeNull()
        ->and($unknown->model())->toBeNull();

    $record->delete();

    expect($plain->model())->toBeNull();
});

it('keeps the events serializable for queued listeners', function (): void {
    $invoice = invoice();
    $event = new TamperDetected(Invoice::class, $invoice->id, 'financial', VerificationStatus::Tampered, 'mac', ['a:amount'], VerificationContext::Command, 'k');

    $copy = unserialize(serialize($event));

    expect($copy)->toEqual($event)
        ->and($copy->changedColumns())->toBe(['amount'])
        ->and($copy->model()?->is($invoice))->toBeTrue();
});
