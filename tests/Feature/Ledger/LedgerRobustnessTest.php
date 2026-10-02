<?php

declare(strict_types=1);

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RoundlyConsulting\Sentinel\Actions\Seals\ResealModelsAction;
use RoundlyConsulting\Sentinel\Actions\Seals\SealMissingAction;
use RoundlyConsulting\Sentinel\Canonical\BinarySafe;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Engine\Inspector;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\LedgerFindingKind;
use RoundlyConsulting\Sentinel\Exceptions\ConcurrentSealException;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIntegrityException;
use RoundlyConsulting\Sentinel\Exceptions\SealingFailedException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Middleware\VerifySeals;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Testing\Database\DriverMatrix;

/**
 * Run $interfere once (or always) right after the first query matching $sql.
 */
function interfereAfter(string $sql, Closure $interfere, bool $always = false): void
{
    $done = false;

    DB::listen(static function (QueryExecuted $query) use ($sql, $interfere, $always, &$done): void {
        if ((! $done || $always) && str_contains($query->sql, $sql)) {
            $done = true;
            $interfere($query);
        }
    });
}

it('retries a checkpoint that lost the race for its sequence number', function (): void {
    invoice();
    interfereAfter('from "sentinel_ledger"', static fn () => DB::table('sentinel_checkpoints')->insert([
        'seq' => 1, 'first_entry_id' => 0, 'last_entry_id' => 0, 'entries' => 0, 'root' => 'r', 'ring' => 'default',
        'key_id' => 'k', 'algorithm' => 'hmac-sha256', 'mac' => 'm', 'created_at' => '2026-01-01 00:00:00.000000',
    ]));

    // The intruding row rolled back with the losing transaction; the retry made seq 1.
    expect(Sentinel::checkpoint()?->seq)->toBe(1)
        ->and(Checkpoint::query()->count())->toBe(1);
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

it('retries a checkpoint whose entries another run claimed', function (): void {
    invoice();
    interfereAfter('insert into "sentinel_checkpoints"', static fn () => DB::table('sentinel_ledger')
        ->where('id', LedgerEntry::query()->min('id'))->update(['checkpoint_id' => Checkpoint::query()->max('id')]));

    expect(Sentinel::checkpoint()?->entries)->toBe(2)
        ->and(Sentinel::verifyLedger()->clean())->toBeTrue();
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

it('gives up after repeated conflicts', function (): void {
    invoice();
    interfereAfter('insert into "sentinel_checkpoints"', static fn () => DB::table('sentinel_ledger')
        ->where('id', LedgerEntry::query()->min('id'))->update(['checkpoint_id' => Checkpoint::query()->max('id')]), always: true);

    expect(fn () => Sentinel::checkpoint())->toThrow(ConcurrentSealException::class, 'Another checkpoint run raced');
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

/**
 * A deadlock victim (MySQL picks one when two runs' gap locks cross) rolls back whole; the
 * framework retries it `transaction_attempts` times, the builder keeps going after that.
 */
function deadlockAfter(string $sql, int $times): void
{
    $thrown = 0;

    DB::listen(static function (QueryExecuted $query) use ($sql, $times, &$thrown): void {
        if ($thrown < $times && str_contains($query->sql, $sql)) {
            $thrown++;

            throw new QueryException($query->connectionName, $query->sql, [], new PDOException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction'));
        }
    });
}

it('retries a checkpoint run chosen as a deadlock victim', function (): void {
    invoice();
    config()->set('sentinel.sealing.transaction_attempts', 2);
    deadlockAfter('insert into "sentinel_checkpoints"', 5);

    expect(Sentinel::checkpoint()?->seq)->toBe(1)
        ->and(Checkpoint::query()->count())->toBe(1)
        ->and(Sentinel::verifyLedger()->clean())->toBeTrue();
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

it('gives up after repeated deadlocks and rethrows anything that is not a race', function (): void {
    invoice();
    config()->set('sentinel.sealing.transaction_attempts', 1);
    deadlockAfter('insert into "sentinel_checkpoints"', PHP_INT_MAX);

    expect(fn () => Sentinel::checkpoint())->toThrow(ConcurrentSealException::class, 'Another checkpoint run raced')
        ->and(Checkpoint::query()->count())->toBe(0);

    DB::listen(static function (QueryExecuted $query): void {
        if (str_contains($query->sql, 'from "sentinel_ledger"')) {
            throw new QueryException($query->connectionName, $query->sql, [], new PDOException('disk I/O error'));
        }
    });

    expect(fn () => Sentinel::checkpoint())->toThrow(QueryException::class, 'disk I/O error');
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'interleaves on the one SQLite connection');

it('checkpoints entries too damaged to read, and reports them', function (): void {
    $invoice = invoice();
    $entries = LedgerEntry::query()->where('sealable_id', $invoice->id)->orderBy('id')->pluck('id')->all();
    LedgerEntry::query()->whereKey($entries[0])->toBase()->update(['event' => 'bogus', 'entry_mac' => '%%%']);
    $binary = corrupt(static fn () => LedgerEntry::query()->whereKey($entries[1])->toBase()->update(['reason' => "\xff\xfe"]));

    Sentinel::checkpoint();
    $kinds = array_map(static fn ($finding): LedgerFindingKind => $finding->kind, Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false))->findings);

    expect(array_count_values(array_map(static fn (LedgerFindingKind $kind): string => $kind->value, $kinds)))->toBe(['entry_invalid' => $binary ? 2 : 1])
        ->and(BinarySafe::value("\xff"))->toBe(['b', '_w'])
        ->and(BinarySafe::value('ok'))->toBe('ok')
        ->and(BinarySafe::value(null))->toBeNull();
});

it('falls back to the ledger rings for a definition that no longer compiles', function (): void {
    $class = definedBy(static fn ($seals) => $seals->seal('once')->attributes('number'));
    $class::query()->create(['number' => 'n']);
    $class::$define = static fn ($seals) => $seals->seal('Invalid Name');
    app()->forgetInstance(DefinitionRegistry::class);

    expect(Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false))->clean())->toBeTrue();
});

it('flags pending entries with a corrupt timestamp', function (): void {
    invoice();
    $written = corrupt(static fn () => LedgerEntry::query()->orderBy('id')->limit(1)->toBase()->update(['occurred_at' => 'yesterday']));

    $kinds = array_map(static fn ($finding): string => $finding->kind->value, Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false))->findings);

    expect($kinds)->toBe($written ? ['entry_invalid', 'backlog'] : []);
});

it('exposes the violations of a failed ledger check', function (): void {
    invoice();
    Sentinel::checkpoint();
    DB::table('sentinel_checkpoints')->update(['mac' => str_repeat('A', 43)]);

    try {
        Sentinel::verifyLedger()->throwIfViolated();
        $this->fail('No violation was thrown.');
    } catch (LedgerIntegrityException $exception) {
        expect($exception->findings())->toHaveCount(1)
            ->and($exception->findings()[0]->toArray())->toMatchArray(['kind' => 'checkpoint_invalid', 'seq' => 1, 'detail' => 'mac']);
    }
});

it('survives a corrupt checkpoint row as a head and a republish source', function (): void {
    invoice();
    Sentinel::checkpoint();
    Checkpoint::query()->toBase()->update(['created_at' => 'garbled', 'algorithm' => 'none']);

    expect(Sentinel::ledger()->head()?->createdAt->getTimestamp())->toBe(0)
        ->and(AnchorCodec::fromCheckpoint(Checkpoint::query()->firstOrFail(), 'x'))->toBeNull()
        ->and(Sentinel::checkpoint())->toBeNull()
        ->and(fn () => AnchorCodec::decode(AnchorCodec::encode(new AnchorPayload('c', 1, 'r', Sentinel::ledger()->head()->createdAt, 'default', 'k', Algorithm::HmacSha256, 'm'))))->not->toThrow(Throwable::class)
        ->and(fn () => AnchorCodec::decode('{"v":"sentinel.anchor/1","conn":"c","seq":"1","root":"r","at":"2026-13-45T99:00:00.000000Z","ring":"default","kid":"k","alg":"hmac-sha256","mac":"m"}'))->toThrow(CorruptRecordException::class, '[at]');
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'only SQLite stores a garbled datetime');

it('counts failures of the bulk operations instead of aborting', function (): void {
    $invoice = invoice();
    $reseal = app(ResealModelsAction::class);
    $baseline = app(SealMissingAction::class);
    $seal = app(DefinitionRegistry::class)->seal($invoice);
    $gone = invoice();
    DB::table('invoices')->where('id', $gone->id)->delete();

    expect((new ReflectionMethod($reseal, 'rotate'))->invoke($reseal, $gone, $seal, null))->toBe('failed')
        ->and((new ReflectionMethod($baseline, 'baseline'))->invoke($baseline, $gone, $seal, 'x', null))->toBe('failed')
        ->and((new ReflectionMethod($baseline, 'baseline'))->invoke($baseline, $invoice, $seal, 'x', null))->toBeNull()
        ->and(fn () => app(Inspector::class)->values($gone, $seal))->toThrow(SealingFailedException::class);
});

it('counts acknowledgements that cannot be sealed as failures', function (): void {
    $invoice = invoice();

    if (! corrupt(static fn () => DB::table('invoices')->where('id', $invoice->id)->update(['currency' => "\xff\xfe\xfd"]))) {
        return;
    }

    expect(Sentinel::model(Invoice::class)->reseal('financial', acknowledgeReason: 'fix')->failed)->toBe(1)
        ->and(Sentinel::model(Invoice::class)->reseal('financial', dryRun: true, acknowledgeReason: 'fix')->acknowledged)->toBe(1)
        ->and(Sentinel::model(Invoice::class)->resealWhere(Invoice::query(), 'fix', seal: 'financial')->failed)->toBe(1);
});

it('wraps a non-response from the next middleware', function (): void {
    $response = app(VerifySeals::class)->handle(Request::create('/x'), static fn (): string => 'plain');

    expect($response->getContent())->toBe('plain');
});

it('prints ledger findings as JSON', function (): void {
    Event::fake();
    invoice();
    Sentinel::checkpoint();
    DB::table('sentinel_checkpoints')->update(['mac' => str_repeat('A', 43)]);

    Artisan::call('sentinel:verify', ['--ledger' => true, '--json' => true]);
    $report = json_decode(Artisan::output(), true, 16, JSON_THROW_ON_ERROR);

    expect($report['ledger']['findings'][0])->toMatchArray(['kind' => 'checkpoint_invalid', 'detail' => 'mac', 'seq' => 1]);
});
