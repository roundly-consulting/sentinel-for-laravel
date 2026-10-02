<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Random\Engine\Mt19937;
use Random\Randomizer;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Anchors\MemoryAnchor;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\PlainRecord;
use RoundlyConsulting\Sentinel\Tests\Support\ReferenceSentinel;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Property test (plan §12.6): 200 seeded sequences of 25 random operations — Eloquent
 * writes, out-of-band tampering, seal deletion, snapshot + restore of a row and its seal,
 * acknowledgements, key rotation, re-sealing, deletes, checkpoints and ledger checks without
 * the external anchor. After every step the engine must agree with ReferenceSentinel (a pure
 * model of the semantics contract) on each model's verification status, its seal and ledger
 * versions, and the ledger check's findings (anchored; unanchored as a step and at the end).
 *
 * SQLite only: it is a semantics check; the real-engine legs race the engine instead.
 */
const PROPERTY_SEQUENCES = 200;

const PROPERTY_STEPS = 25;

/**
 * @return array<string, array{0: int}>
 */
function propertySequences(): array
{
    $master = new Randomizer(new Mt19937(20261002));
    $sequences = [];

    for ($i = 1; $i <= PROPERTY_SEQUENCES; $i++) {
        $sequences["sequence {$i}"] = [$master->getInt(1, 2_147_483_647)];
    }

    return $sequences;
}

/**
 * The engine's view of one model: seal row version and ledger head version.
 *
 * @return array{seal: int|null, head: int}
 */
function engineVersions(int $id): array
{
    $type = (new PlainRecord)->getMorphClass();
    $seal = Seal::query()->where('sealable_type', $type)->where('sealable_id', $id)->value('version');

    return [
        'seal' => $seal === null ? null : (int) $seal,
        'head' => (int) LedgerEntry::query()->where('sealable_type', $type)->where('sealable_id', $id)->max('version'),
    ];
}

/**
 * @return list<string>
 */
function engineLedgerFindings(): array
{
    $findings = array_map(
        static fn (LedgerFinding $finding): string => $finding->kind->value.':'.($finding->sealableId ?? '-'),
        Sentinel::verifyLedger()->findings,
    );
    sort($findings);

    return $findings;
}

if (DriverMatrix::driver() !== 'sqlite') {
    it('agrees with the reference model after every step')->skip('the property test runs on SQLite (plan §12.6)')->group('property');

    return;
}

it('agrees with the reference model after every step', function (int $seed): void {
    Carbon::setTestNow(CarbonImmutable::parse('2026-10-02 18:00:00.000000', 'UTC'));
    config()->set('logging.default', 'null');
    config()->set('sentinel.keys.rings.default.driver', 'database');
    app(KeyStoreManager::class)->flush();
    MemoryAnchor::install();

    $random = new Randomizer(new Mt19937($seed));
    $reference = new ReferenceSentinel(Sentinel::keys()->ring()->generate(Algorithm::HmacSha256)->info->keyId);
    $type = (new PlainRecord)->getMorphClass();
    $snapshots = [];
    $log = ["seed {$seed}"];
    $operations = [
        'update' => 4, 'tamper' => 2, 'delete-seal' => 1, 'snapshot' => 2, 'restore' => 2, 'acknowledge' => 3,
        'rotate' => 1, 'reseal' => 2, 'delete' => 1, 'checkpoint' => 2, 'create' => 2, 'verify-unanchored' => 2,
    ];
    $bag = [];

    foreach ($operations as $operation => $weight) {
        array_push($bag, ...array_fill(0, $weight, $operation));
    }

    try {
        for ($step = 1; $step <= PROPERTY_STEPS; $step++) {
            Carbon::setTestNow(Carbon::now()->addSecond());
            $alive = $reference->alive();
            $operation = $bag[$random->getInt(0, count($bag) - 1)];

            if ($alive === [] || ($operation === 'create' && count($alive) >= 3)) {
                $operation = $alive === [] ? 'create' : 'update';
            }

            $id = $alive === [] ? 0 : $alive[$random->getInt(0, count($alive) - 1)];
            $value = $random->getInt(0, 1000);

            if ($operation === 'restore' && ! $reference->hasSnapshot($id)) {
                $operation = 'snapshot';
            }

            if (in_array($operation, ['update', 'tamper'], true)) {
                $value = $reference->row($id) + 1 + $value;
            }

            $log[] = "{$step}: {$operation} #{$id} ({$value})";
            $context = implode(' · ', $log);

            switch ($operation) {
                case 'create':
                    $model = PlainRecord::query()->create(['name' => 'property', 'count' => $value]);
                    $reference->created($model->id, $value);

                    break;
                case 'update':
                    $allowed = $reference->update($id, $value);

                    try {
                        PlainRecord::query()->findOrFail($id)->update(['count' => $value]);
                        $written = true;
                    } catch (TamperedModelException) {
                        $written = false;
                    }

                    expect($written)->toBe($allowed, $context);

                    break;
                case 'tamper':
                    DB::table('plain_records')->where('id', $id)->update(['count' => $value]);
                    $reference->tamper($id, $value);

                    break;
                case 'delete-seal':
                    DB::table('sentinel_seals')->where('sealable_type', $type)->where('sealable_id', $id)->delete();
                    $reference->deleteSeal($id);

                    break;
                case 'snapshot':
                    $seal = DB::table('sentinel_seals')->where('sealable_type', $type)->where('sealable_id', $id)->first();
                    $snapshots[$id] = [
                        'row' => DB::table('plain_records')->where('id', $id)->value('count'),
                        'seal' => $seal === null ? null : (array) $seal,
                    ];
                    $reference->snapshot($id);

                    break;
                case 'restore':
                    DB::table('plain_records')->where('id', $id)->update(['count' => $snapshots[$id]['row']]);
                    DB::table('sentinel_seals')->where('sealable_type', $type)->where('sealable_id', $id)->delete();

                    if ($snapshots[$id]['seal'] !== null) {
                        DB::table('sentinel_seals')->insert($snapshots[$id]['seal']);
                    }

                    $reference->restore($id);

                    break;
                case 'acknowledge':
                    $acknowledged = Sentinel::acknowledge(PlainRecord::query()->findOrFail($id), "INC-{$step}: reviewed")->acknowledged;

                    expect($acknowledged)->toBe($reference->acknowledge($id), $context);

                    break;
                case 'rotate':
                    $reference->rotated(Sentinel::keys()->ring()->rotate()->current->keyId);

                    break;
                case 'reseal':
                    expect(Sentinel::model(PlainRecord::class)->reseal()->resealed)->toBe($reference->reseal(), $context);

                    break;
                case 'delete':
                    PlainRecord::query()->findOrFail($id)->delete();
                    $reference->deleted($id);

                    break;
                case 'checkpoint':
                    Sentinel::checkpoint();

                    break;
                case 'verify-unanchored':
                    config()->set('sentinel.ledger.anchors', '');

                    expect(engineLedgerFindings())->toBe($reference->ledgerFindings(), "unanchored ledger after {$context}");

                    config()->set('sentinel.ledger.anchors', 'memory');

                    break;
            }

            foreach ($reference->alive() as $each) {
                $result = Sentinel::verify(PlainRecord::query()->findOrFail($each));

                expect([$result->status->value, $result->reason])->toBe($reference->status($each), "#{$each} after {$context}")
                    ->and(engineVersions($each))->toBe($reference->versions($each), "#{$each} after {$context}");
            }

            expect(engineLedgerFindings())->toBe($reference->ledgerFindings(), "anchored ledger after {$context}");
        }

        config()->set('sentinel.ledger.anchors', '');

        expect(engineLedgerFindings())->toBe($reference->ledgerFindings(), 'unanchored ledger at the end of '.implode(' · ', $log));
    } finally {
        Carbon::setTestNow();
    }
})->with(propertySequences())->group('property');
