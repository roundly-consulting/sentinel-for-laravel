<?php

declare(strict_types=1);

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;

it('records checkpoints and ledger verification without touching the ledger', function (): void {
    invoice();
    $fake = Sentinel::fake();

    $fake->assertCheckpointed(0);

    expect(Sentinel::ledger()->checkpoint())->toBeNull()
        ->and(Sentinel::ledger()->verify()->clean())->toBeTrue()
        ->and(Sentinel::ledger()->head())->toBeNull()
        ->and(Sentinel::ledger()->history(Invoice::query()->firstOrFail()))->toBe([])
        ->and(Sentinel::ledger()->anchors())->toBe([])
        ->and(Checkpoint::query()->count())->toBe(0)
        ->and(fn () => Sentinel::checkpoint(new CheckpointOptions(batchSize: 0)))->toThrow(InvalidSentinelConfigurationException::class);

    Sentinel::assertCheckpointed();
    $fake->assertCheckpointed(1);

    expect(fn () => $fake->assertCheckpointed(3))->toThrow(ExpectationFailedException::class, '3 ledger checkpoint(s)');
});

it('fails assertCheckpointed when nothing was checkpointed', function (): void {
    Sentinel::fake()->assertCheckpointed();
})->throws(ExpectationFailedException::class, 'Expected a ledger checkpoint');

it('runs the bulk operations over faked statuses', function (): void {
    $intact = invoice();
    $tampered = invoice(['status' => 'draft']);
    $fake = Sentinel::fake();
    $fake->fakeStatus($tampered, VerificationStatus::Tampered, 'financial');

    $scan = Sentinel::model(Invoice::class)->scan();
    $reseal = Sentinel::model(Invoice::class)->reseal();
    $acknowledged = Sentinel::model(Invoice::class)->reseal('financial', acknowledgeReason: 'reviewed');

    expect($scan->scanned)->toBe(4)
        ->and($scan->count(VerificationStatus::Tampered))->toBe(1)
        ->and($reseal->resealed)->toBe(3)
        ->and($reseal->skippedResults[0]->sealableId)->toBe($tampered->id)
        ->and($acknowledged->acknowledged)->toBe(1)
        ->and(Sentinel::verify($tampered)->status)->toBe(VerificationStatus::Intact);

    $fake->assertResealed(Invoice::class);
    $fake->assertResealed(Invoice::class, 5);
    $fake->assertAcknowledged($tampered, 'reviewed');

    expect(fn () => $fake->assertResealed(PlainRecord::class))->toThrow(ExpectationFailedException::class, 'to be re-sealed')
        ->and(fn () => $fake->assertResealed(Invoice::class, 9))->toThrow(ExpectationFailedException::class, 'but 5 were')
        ->and([$intact->id])->not->toBeEmpty();
});

it('keeps the real refusals of the bulk operations under the fake', function (): void {
    $draft = invoice(['status' => 'draft', 'currency' => 'USD']);
    $fake = Sentinel::fake();

    $updated = Sentinel::model(Invoice::class)->updateAndReseal(static fn (Builder $query) => $query->where('status', 'draft'), ['currency' => 'EUR'], 'migration');

    expect($updated->resealed)->toBe(1)
        ->and(DB::table('invoices')->where('id', $draft->id)->value('currency'))->toBe('EUR');

    $fake->fakeStatus($draft, VerificationStatus::Tampered);

    expect(fn () => Sentinel::model(Invoice::class)->updateAndReseal(Invoice::query(), ['currency' => 'GBP'], 'again'))->toThrow(TamperedModelException::class)
        ->and(fn () => Sentinel::model(Invoice::class)->updateAndReseal(Invoice::query(), ['bad column' => 1], 'x'))->toThrow(SealingMisconfiguredException::class)
        ->and(fn () => Sentinel::model(Invoice::class)->resealWhere(PlainRecord::query(), 'x'))->toThrow(SealingMisconfiguredException::class)
        ->and(DB::table('invoices')->where('id', $draft->id)->value('currency'))->toBe('EUR')
        ->and(Sentinel::model(Invoice::class)->resealWhere(Invoice::query(), 'bulk ack', seal: 'financial')->acknowledged)->toBe(1)
        ->and(Sentinel::model(Invoice::class)->updateAndReseal(Invoice::query()->whereKey(0), ['currency' => 'GBP'], 'none')->resealed)->toBe(0);

    $fake->fakeStatus($draft, VerificationStatus::Missing, 'financial');
    $baseline = Sentinel::model(Invoice::class)->sealMissing('baseline');

    expect($baseline->resealed)->toBe(1)
        ->and($baseline->skipped)->toBe(1);

    $fake->assertResealed(Invoice::class, 3);
});
