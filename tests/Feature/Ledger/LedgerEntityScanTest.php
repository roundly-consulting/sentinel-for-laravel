<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;

/**
 * @return list<string>
 */
function entityFindings(bool $entities = true): array
{
    return array_map(
        static fn (LedgerFinding $finding): string => $finding->kind->value.'#'.$finding->sealableId.'@'.$finding->seal,
        Sentinel::verifyLedger(new LedgerVerifyOptions(entities: $entities))->findings,
    );
}

/**
 * §10 item 39: every live ledger head must still have its row and its seal, at that version.
 */
it('finds rows deleted without a tombstone (§3.2 #12)', function (): void {
    $invoice = invoice();
    DB::table('invoices')->where('id', $invoice->id)->delete();

    expect(entityFindings())->toBe(["entity_deleted#{$invoice->id}@financial", "entity_deleted#{$invoice->id}@identity"])
        ->and(entityFindings(entities: false))->toBe([]);
});

it('ignores histories that ended with a tombstone', function (): void {
    $deleted = invoice();
    $deleted->forceDelete();
    $unsealed = invoice();
    Sentinel::unseal($unsealed, 'retired record', seal: 'identity');
    $soft = invoice();
    $soft->delete();

    expect(entityFindings())->toBe([]);
});

it('finds seal rows that are missing or rolled back', function (): void {
    $missing = invoice();
    $rolledBack = invoice(['amount' => '1.00']);
    $old = Seal::query()->where('sealable_id', $rolledBack->id)->where('seal', 'financial')->value('version');
    $rolledBack->update(['amount' => '2.00']);

    Seal::query()->where('sealable_id', $missing->id)->where('seal', 'identity')->delete();
    Seal::query()->where('sealable_id', $rolledBack->id)->where('seal', 'financial')->toBase()->update(['version' => $old]);

    expect(entityFindings())->toBe(["seal_missing#{$missing->id}@identity", "seal_rolled_back#{$rolledBack->id}@financial"]);
});

it('cannot resolve the entities of an unknown model class', function (): void {
    $invoice = invoice();
    LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'identity')->toBase()->update(['sealable_type' => 'App\\Gone']);

    expect(entityFindings())->toContain("entity_deleted#{$invoice->id}@identity")
        ->and(entityFindings())->toContain("entry_invalid#{$invoice->id}@identity");
});

it('reports a stalled checkpoint job as a backlog, not a violation', function (): void {
    Carbon::setTestNow(CarbonImmutable::parse('2026-10-02 10:00:00', 'UTC'));

    try {
        invoice();
        Carbon::setTestNow(CarbonImmutable::parse('2026-10-02 10:09:00', 'UTC'));
        $fresh = Sentinel::verifyLedger();

        Carbon::setTestNow(CarbonImmutable::parse('2026-10-02 10:11:00', 'UTC'));
        $stale = Sentinel::verifyLedger();
    } finally {
        Carbon::setTestNow();
    }

    expect($fresh->findings)->toBe([])
        ->and($stale->findings[0]->kind)->toBe(LedgerFindingKind::Backlog)
        ->and($stale->findings[0]->detail)->toContain('2 entries')
        ->and($stale->clean())->toBeTrue()
        ->and($stale->has(LedgerFindingKind::Backlog))->toBeTrue()
        ->and($stale->has(LedgerFindingKind::ChainBroken))->toBeFalse();
});

it('verifies the MACs of entries not checkpointed yet', function (): void {
    $invoice = invoice();
    LedgerEntry::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->toBase()->update(['actor_type' => 'users', 'actor_id' => 1]);

    expect(entityFindings())->toBe(["entry_invalid#{$invoice->id}@financial"]);
});

it('verifies every configured connection', function (): void {
    invoice();
    config()->set('sentinel.ledger.connections', [null, DB::getDefaultConnection()]);

    expect(Settings::ledgerConnections())->toBe([null, DB::getDefaultConnection()])
        ->and(Sentinel::verifyLedger()->entries)->toBe(4);

    foreach ([[], 'testing', [''], [1]] as $invalid) {
        config()->set('sentinel.ledger.connections', $invalid);

        expect(fn () => Settings::ledgerConnections())->toThrow(InvalidSentinelConfigurationException::class);
    }
});

it('reads the ledger settings strictly', function (): void {
    config()->set('sentinel.models', [Invoice::class]);
    expect(Settings::models())->toBe([Invoice::class]);

    foreach (['x', [stdClass::class], ['k' => Invoice::class]] as $invalid) {
        config()->set('sentinel.models', $invalid);

        expect(fn () => Settings::models())->toThrow(InvalidSentinelConfigurationException::class);
    }

    config()->set('sentinel.ledger.anchor_drivers.cache', 'x');
    expect(fn () => Settings::anchorDriver('cache'))->toThrow(InvalidSentinelConfigurationException::class);

    config()->set('sentinel.middleware.verified_reaction', 'ignore');
    expect(fn () => Settings::verifiedAborts())->toThrow(InvalidSentinelConfigurationException::class);
});
