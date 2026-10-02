<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Actions\Ledger\CreateCheckpointAction;
use RoundlyConsulting\Sentinel\Canonical\CheckpointMessage;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Events\LedgerCheckpointed;
use RoundlyConsulting\Sentinel\Events\LedgerIntegrityViolated;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIntegrityException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Ledger\ChainHasher;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Testing\Database\DriverMatrix;
use RoundlyConsulting\Testing\Fixtures\LockRecorder;
use RoundlyConsulting\Testing\Fixtures\LockRecordingGrammar;

/**
 * @return list<LedgerFindingKind>
 */
function findingKinds(LedgerReport $report): array
{
    return array_map(static fn ($finding): LedgerFindingKind => $finding->kind, $report->findings);
}

/**
 * §10 item 37: checkpoints chain batches of ledger entries under a keyed MAC.
 */
it('folds pending entries into chained, MAC\'d checkpoints', function (): void {
    Event::fake([LedgerCheckpointed::class]);
    invoice();
    invoice();

    $first = Sentinel::ledger()->checkpoint();

    expect($first?->seq)->toBe(1)
        ->and($first?->entries)->toBe(4)
        ->and($first?->connection)->toBe(DB::getDefaultConnection())
        ->and($first?->anchors)->toBe([])
        ->and(LedgerEntry::query()->whereNull('checkpoint_id')->count())->toBe(0)
        ->and(Sentinel::ledger()->checkpoint())->toBeNull();

    invoice();
    $second = Sentinel::checkpoint(new CheckpointOptions);
    $head = Sentinel::ledger()->head();

    expect($second?->seq)->toBe(2)
        ->and(Checkpoint::query()->where('seq', 2)->value('previous_digest'))->toBe($first?->root)
        ->and($head?->seq)->toBe(2)
        ->and($head?->root)->toBe($second?->root)
        ->and($head?->entries)->toBe(2)
        ->and($head?->keyId)->toBe('test-default');

    $report = Sentinel::ledger()->verify();

    expect($report->clean())->toBeTrue()
        ->and($report->findings)->toBe([])
        ->and($report->checkpoints)->toBe(2)
        ->and($report->entries)->toBe(6);

    $report->throwIfViolated();

    Event::assertDispatchedTimes(LedgerCheckpointed::class, 2);
});

it('splits the backlog into batches and chains every batch', function (): void {
    foreach (range(1, 3) as $ignored) {
        invoice();
    }

    $seqs = [];

    while (($result = Sentinel::checkpoint(new CheckpointOptions(batchSize: 4))) !== null) {
        $seqs[] = [$result->seq, $result->entries];
    }

    expect($seqs)->toBe([[1, 4], [2, 2]])
        ->and(Sentinel::verifyLedger()->clean())->toBeTrue()
        ->and(fn () => Sentinel::checkpoint(new CheckpointOptions(batchSize: 0)))->toThrow(InvalidSentinelConfigurationException::class);
});

it('commits to exactly the chain of entry documents and MACs', function (): void {
    invoice();
    $result = app(CreateCheckpointAction::class)->execute(new CheckpointOptions);
    $chain = new ChainHasher;
    $state = $chain->start(null);

    foreach (LedgerEntry::query()->orderBy('id')->get() as $entry) {
        $state = $chain->next($state, $entry);
    }

    expect($chain->root($state))->toBe($result?->root)
        ->and(strlen($chain->start($result?->root)))->toBe(32)
        ->and(strlen($chain->start('not-a-root')))->toBe(32);
});

it('lets late-committing entries join a later checkpoint', function (): void {
    invoice();
    $late = invoice();
    invoice();

    // The middle invoice's entries commit "late": invisible while the first checkpoint runs.
    $rows = DB::table('sentinel_ledger')->where('sealable_id', $late->id)->get()->map(static fn (object $row): array => (array) $row)->all();
    $links = DB::table('sentinel_seals')->where('sealable_id', $late->id)->pluck('ledger_entry_id', 'id')->all();
    DB::table('sentinel_seals')->where('sealable_id', $late->id)->update(['ledger_entry_id' => null]);
    DB::table('sentinel_ledger')->where('sealable_id', $late->id)->delete();

    $first = Sentinel::checkpoint();

    DB::table('sentinel_ledger')->insert($rows);

    foreach ($links as $seal => $entry) {
        DB::table('sentinel_seals')->where('id', $seal)->update(['ledger_entry_id' => $entry]);
    }

    $second = Sentinel::checkpoint();
    $ids = array_map(static fn (array $row): int => (int) $row['id'], $rows);

    expect($first?->entries)->toBe(4)
        ->and($second?->entries)->toBe(2)
        ->and(Checkpoint::query()->where('seq', 2)->value('last_entry_id'))->toBe(max($ids))
        ->and(max($ids))->toBeLessThan((int) Checkpoint::query()->where('seq', 1)->value('last_entry_id'))
        ->and(Sentinel::verifyLedger()->clean())->toBeTrue();
});

it('detects every change to checkpointed history', function (Closure $tamper, LedgerFindingKind $kind): void {
    Event::fake([LedgerIntegrityViolated::class]);
    $invoice = invoice();
    Sentinel::checkpoint();
    invoice();
    Sentinel::checkpoint();

    $tamper($invoice);

    $report = Sentinel::verifyLedger();

    expect(findingKinds($report))->toContain($kind)
        ->and($report->clean())->toBeFalse()
        ->and(fn () => $report->throwIfViolated())->toThrow(LedgerIntegrityException::class, $kind->value);

    Event::assertDispatched(LedgerIntegrityViolated::class, static fn (LedgerIntegrityViolated $event): bool => $event->findings !== []);
})->with([
    'an edited entry' => [static fn () => LedgerEntry::query()->where('seal', 'financial')->orderBy('id')->limit(1)->toBase()->update(['reason' => 'rewritten']), LedgerFindingKind::EntryInvalid],
    'a deleted entry' => [static function (): void {
        DB::table('sentinel_seals')->delete();
        DB::table('sentinel_ledger')->where('id', LedgerEntry::query()->min('id'))->delete();
    }, LedgerFindingKind::CheckpointMismatch],
    'a removed checkpoint' => [static function (): void {
        DB::table('sentinel_ledger')->where('checkpoint_id', Checkpoint::query()->where('seq', 1)->value('id'))->update(['checkpoint_id' => null]);
        DB::table('sentinel_checkpoints')->where('seq', 1)->delete();
    }, LedgerFindingKind::CheckpointGap],
    'a replaced checkpoint root' => [static fn () => Checkpoint::query()->where('seq', 1)->toBase()->update(['root' => str_repeat('A', 43)]), LedgerFindingKind::CheckpointInvalid],
    'a re-pointed chain' => [static fn () => Checkpoint::query()->where('seq', 2)->toBase()->update(['previous_digest' => str_repeat('B', 43)]), LedgerFindingKind::ChainBroken],
    'a forged checkpoint MAC' => [static fn () => Checkpoint::query()->where('seq', 2)->toBase()->update(['mac' => str_repeat('C', 43)]), LedgerFindingKind::CheckpointInvalid],
    'a renumbered checkpoint' => [static fn () => Checkpoint::query()->where('seq', 2)->toBase()->update(['seq' => 5]), LedgerFindingKind::CheckpointGap],
]);

it('only trusts checkpoints signed by a usable ledger-ring key', function (Closure $tamper, string $detail): void {
    invoice();
    Sentinel::checkpoint();

    $findings = $tamper() === false ? null : Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false))->findings;

    // null: the engine refused to store the corruption at all.
    expect($findings === null || ($findings[0]->kind === LedgerFindingKind::CheckpointInvalid && $findings[0]->detail === $detail))->toBeTrue();
})->with([
    'another ring' => [static fn () => Checkpoint::query()->toBase()->update(['ring' => 'http']), 'ring_not_accepted'],
    'an unknown key' => [static fn () => Checkpoint::query()->toBase()->update(['key_id' => 'gone']), 'not_found'],
    'a revoked key' => [static fn () => config()->set('sentinel.keys.revoked', 'default:test-default'), 'revoked_key'],
    'another algorithm' => [static fn () => Checkpoint::query()->toBase()->update(['algorithm' => 'ed25519']), 'algorithm_mismatch'],
    'a corrupt timestamp' => [static fn (): bool => corrupt(static fn () => Checkpoint::query()->toBase()->update(['created_at' => '2026-13-45 99:99:99'])), 'malformed'],
    'an undecodable MAC' => [static fn () => Checkpoint::query()->toBase()->update(['mac' => '%%%']), 'malformed'],
]);

it('keeps ledger evidence verifiable after its key is retired', function (): void {
    config()->set('sentinel.keys.rings.default.driver', 'chain');
    $old = Sentinel::keys()->ring()->generate(Algorithm::HmacSha512, 'db-key');
    config()->set('sentinel.keys.rings.default.key_id', null);
    config()->set('sentinel.keys.rings.default.key', null);
    app(KeyStoreManager::class)->flush();

    invoice();
    Sentinel::checkpoint();
    Key::query()->where('kid', $old->info->keyId)->firstOrFail();
    Sentinel::keys()->ring()->rotate();
    Sentinel::keys()->ring()->retire($old->info->keyId);

    $report = Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false));

    expect(findingKinds($report))->not->toContain(LedgerFindingKind::CheckpointInvalid)
        ->and(findingKinds($report))->not->toContain(LedgerFindingKind::EntryInvalid);
});

it('signs checkpoints with the configured ledger ring only', function (): void {
    invoice();
    config()->set('sentinel.ledger.ring', 'nope');

    expect(fn () => Settings::ledgerRing())->toThrow(InvalidSentinelConfigurationException::class)
        ->and(fn () => Sentinel::checkpoint())->toThrow(InvalidSentinelConfigurationException::class);

    config()->set('sentinel.ledger.ring', null);

    expect(Settings::ledgerRing())->toBe('default')
        ->and(Settings::ledgerRings())->toBe(['default']);
});

it('checkpoints through the injected manager and the raw action alike', function (): void {
    invoice();

    expect(app(SentinelManager::class)->checkpoint(new CheckpointOptions)?->seq)->toBe(1)
        ->and(app(CreateCheckpointAction::class)->execute(new CheckpointOptions))->toBeNull()
        ->and(Sentinel::ledger()->anchors())->toBe([])
        ->and(CheckpointMessage::VERSION)->toBe('sentinel.checkpoint/1');
});

it('locks the checkpoint tail before the entries it claims', function (): void {
    invoice();
    $connection = DB::connection();
    $connection->setQueryGrammar(new LockRecordingGrammar($connection));
    LockRecorder::flush();
    LockRecorder::listenForMarkers();

    Sentinel::checkpoint();

    $tables = array_map(static fn (array $lock): string => str_contains($lock['sql'], 'sentinel_checkpoints') ? 'tail' : (str_contains($lock['sql'], 'sentinel_ledger') ? 'entries' : 'other'), LockRecorder::recorded());

    // The tail is locked (and re-locked until stable) before any entry.
    expect($tables)->toBe(['tail', 'tail', 'entries'])
        ->and(array_unique(array_map(static fn (array $lock): int => $lock['transactionDepth'], LockRecorder::recorded())))->toBe([1]);
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'the recording grammar is SQLite-only; the real-engine legs lock for real');
