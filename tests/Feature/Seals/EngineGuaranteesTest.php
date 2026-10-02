<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use RoundlyConsulting\Sentinel\Canonical\Normalizer;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Definition\SealType;
use RoundlyConsulting\Sentinel\Engine\DocumentBuilder;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\LedgerIsAppendOnlyException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Models\LedgerEntry;
use RoundlyConsulting\Sentinel\Models\Seal;
use RoundlyConsulting\Sentinel\Support\Settings;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Models\Invoice;
use RoundlyConsulting\Testing\Database\DriverMatrix;
use RoundlyConsulting\Testing\Fixtures\LockRecorder;
use RoundlyConsulting\Testing\Fixtures\LockRecordingGrammar;

/**
 * Lock order (plan §4.5.6): a sealed update locks the model row, then its seal rows, inside
 * one transaction — before the host's own UPDATE.
 */
it('locks the model row before the seal rows, inside the write transaction', function (): void {
    $invoice = invoice();
    $connection = DB::connection();
    $connection->setQueryGrammar(new LockRecordingGrammar($connection));
    LockRecorder::flush();
    LockRecorder::listenForMarkers();

    $invoice->update(['amount' => '2.00']);

    $locks = LockRecorder::recorded();
    $tables = array_map(static fn (array $lock): string => str_contains($lock['sql'], 'sentinel_seals') ? 'seal' : (str_contains($lock['sql'], '"invoices"') ? 'model' : 'other'), $locks);

    expect($locks)->not->toBeEmpty()
        ->and($tables[0])->toBe('model')
        ->and(array_search('seal', $tables, true))->toBeGreaterThan(0)
        ->and(array_unique(array_map(static fn (array $lock): int => $lock['transactionDepth'], $locks)))->toBe([1])
        ->and($tables)->not->toContain('other');
})->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'the recording grammar is SQLite-only; the real-engine legs lock for real');

/**
 * The same lock order on every path that writes a seal, so two of them can never deadlock:
 * the model row is always locked before any seal row, inside the path's own transaction.
 */
it('locks the model row before its seal rows on every sealing path', function (Closure $operation): void {
    $invoice = invoice();
    $connection = DB::connection();
    $connection->setQueryGrammar(new LockRecordingGrammar($connection));
    LockRecorder::flush();
    LockRecorder::listenForMarkers();

    $operation($invoice);

    $locks = LockRecorder::recorded();
    $tables = array_map(static fn (array $lock): string => str_contains($lock['sql'], 'sentinel_seals') ? 'seal' : (str_contains($lock['sql'], '"invoices"') ? 'model' : 'other'), $locks);

    expect($tables)->toContain('seal')
        ->and($tables[0])->toBe('model')
        ->and($tables)->not->toContain('other')
        ->and(min(array_map(static fn (array $lock): int => $lock['transactionDepth'], $locks)))->toBeGreaterThanOrEqual(1);
})->with([
    'acknowledge' => [static function (Invoice $invoice): void {
        DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.00']);
        Sentinel::acknowledge($invoice, 'INC-3');
    }],
    'explicit seal' => [static fn (Invoice $invoice) => Sentinel::seal($invoice)],
    'unseal' => [static fn (Invoice $invoice) => Sentinel::unseal($invoice, 'archived', seal: 'identity')],
    'mass update' => [static fn (Invoice $invoice) => Sentinel::model(Invoice::class)->updateAndReseal(fn ($query) => $query->whereKey($invoice->id), ['note' => 'n'], 'FIN-1')],
    'delete' => [static fn (Invoice $invoice) => $invoice->forceDelete()],
])->skip(fn (): bool => DriverMatrix::driver() !== 'sqlite', 'the recording grammar is SQLite-only; the real-engine legs lock for real');

/**
 * §10 item 55: every stored datetime and every datetime inside a MAC is UTC.
 */
it('stores and seals UTC regardless of the process and app time zones', function (): void {
    Carbon::setTestNow(CarbonImmutable::parse('2026-10-02 20:30:00.123456', 'Europe/Bratislava'));

    try {
        $invoice = invoice();
        $seal = Seal::query()->where('sealable_id', $invoice->id)->where('seal', 'financial')->firstOrFail();

        expect($seal->getRawOriginal('sealed_at'))->toBe('2026-10-02 18:30:00.123456')
            ->and($seal->sealed_at->getTimezone()->getName())->toBe('UTC')
            ->and(LedgerEntry::query()->value('occurred_at')?->format('H:i:s.u'))->toBe('18:30:00.123456')
            ->and(Sentinel::verify($invoice)->sealedAt?->format('Y-m-d H:i:s.u e'))->toBe('2026-10-02 18:30:00.123456 UTC');
    } finally {
        Carbon::setTestNow();
    }
});

/**
 * §10 item 56: env strings are booleans the way a human means them.
 */
it('reads every boolean switch the way an env string means it', function (string $key, Closure $read, string|bool $value, bool $expected): void {
    config()->set($key, $value);

    expect($read())->toBe($expected);
})->with([
    ['sentinel.sealing.auto', fn () => Settings::autoSeal()],
    ['sentinel.sealing.allow_suspension', fn () => Settings::allowSuspension()],
    ['sentinel.sealing.field_tags', fn () => Settings::fieldTags()],
    ['sentinel.verification.check_ledger', fn () => Settings::checkLedger()],
    ['sentinel.verification.outdated_is_intact', fn () => Settings::outdatedIsIntact()],
    ['sentinel.ledger.enabled', fn () => Settings::ledgerEnabled()],
    ['sentinel.verification.retrieve_checks_ledger', fn () => Settings::retrieveChecksLedger()],
    ['sentinel.idempotency.accept_unquoted', fn () => Settings::idempotencyAcceptsUnquoted()],
    ['sentinel.idempotency.store_client_errors', fn () => Settings::storesClientErrors()],
    ['sentinel.idempotency.store_server_errors', fn () => Settings::storesServerErrors()],
    ['sentinel.idempotency.transactional', fn () => Settings::idempotencyTransactional()],
    ['sentinel.idempotency.encrypt', fn () => Settings::idempotencyEncrypt()],
    ['sentinel.signatures.advertise', fn () => Settings::advertisesSignatures()],
    ['sentinel.signatures.outbound.include_alg', fn () => Settings::outboundIncludesAlg()],
    ['sentinel.signatures.profiles.default.require_query', fn () => ProfileResolver::resolve()->requireQuery],
    ['sentinel.signatures.profiles.default.require_content_digest', fn () => ProfileResolver::resolve()->requireContentDigest],
    ['sentinel.signatures.profiles.default.require_nonce', fn () => ProfileResolver::resolve()->requireNonce],
])->with([
    ['off', false], ['no', false], ['0', false], ['false', false], ['', false], [false, false],
    ['on', true], ['yes', true], ['1', true], ['true', true], [true, true],
]);

it('validates the integer and enum sealing settings', function (): void {
    config()->set('sentinel.sealing.on_tampered_write', 'launder');
    expect(fn () => Settings::onTamperedWrite())->toThrow(InvalidSentinelConfigurationException::class, 'sentinel.sealing.on_tampered_write');

    config()->set('sentinel.sealing.transaction_attempts', 0);
    expect(fn () => Settings::transactionAttempts())->toThrow(InvalidSentinelConfigurationException::class, 'transaction_attempts');

    config()->set('sentinel.sealing.reason_max_length', '50');
    expect(Settings::reasonMaxLength())->toBe(50);

    config()->set('sentinel.verification.log_channel', 'security');
    config()->set('sentinel.acknowledgement.ability', '');
    expect(Settings::logChannel())->toBe('security')->and(Settings::acknowledgementAbility())->toBeNull();
});

/**
 * §10 item 36 (append-only part).
 */
it('refuses to update or delete ledger entries and checkpoints through Eloquent', function (): void {
    invoice();
    $entry = LedgerEntry::query()->firstOrFail();
    $checkpoint = Checkpoint::factory()->create();

    expect(fn () => $entry->update(['reason' => 'x']))->toThrow(LedgerIsAppendOnlyException::class, 'sentinel_ledger')
        ->and(fn () => $entry->delete())->toThrow(LedgerIsAppendOnlyException::class)
        ->and(fn () => $checkpoint->update(['root' => 'x']))->toThrow(LedgerIsAppendOnlyException::class, 'sentinel_checkpoints')
        ->and(fn () => $checkpoint->delete())->toThrow(LedgerIsAppendOnlyException::class)
        ->and($entry->sealable)->toBeInstanceOf(Invoice::class)
        ->and($entry->checkpoint)->toBeNull()
        ->and($entry->actor)->toBeNull()
        ->and(Seal::query()->firstOrFail()->ledgerEntry?->is($entry))->toBeTrue()
        ->and(Seal::query()->firstOrFail()->sealable)->toBeInstanceOf(Invoice::class)
        ->and(Seal::query()->firstOrFail()->sealedBy)->toBeNull();
});

it('builds factory rows for negative tests', function (): void {
    $invoice = invoice();
    Seal::query()->delete();
    Seal::factory()->forSealable($invoice, 'financial')->create();
    LedgerEntry::factory()->forSealable($invoice, 'financial')->tombstone()->create(['version' => 9]);

    // An unsigned seal row never verifies.
    expect(Sentinel::verify($invoice)->status)->not->toBe(VerificationStatus::Intact)
        ->and(LedgerEntry::query()->where('version', 9)->value('seal_mac'))->toBeNull();
});

/**
 * §10 item 28: the same logical row canonicalizes to the same bytes on every engine. Each
 * real-engine leg asserts the identical frozen tuples.
 */
it('canonicalizes a row to the same bytes on every engine', function (): void {
    Carbon::setTestNow(CarbonImmutable::parse('2026-10-02 18:30:00', 'UTC'));

    try {
        $invoice = invoice([
            'customer_id' => 1234567890123, 'amount' => '-0.10', 'status' => 'paid', 'paid' => false, 'due_on' => '2026-02-28',
            'meta' => ['z' => [1, 2.5, ['b' => true, 'a' => null]], 'a' => 'é'], 'secret' => 'ü', 'number' => 'N°7',
        ]);
        $invoice->lines()->create(['sku' => 'X', 'quantity' => 3]);

        $registry = app(DefinitionRegistry::class);
        $tuples = [];

        foreach (['financial', 'identity'] as $name) {
            $seal = $registry->seal($invoice, $name);
            $row = app(ReadBack::class)->row($invoice, $seal->readColumns()) ?? [];
            $message = app(DocumentBuilder::class)->build($invoice, $seal, $seal->fields, $row, 'default', 'k', Algorithm::HmacSha256, 1, null, CarbonImmutable::now());
            $tuples[$name] = array_map(static fn ($field): array => $field->tuple(), $message->fields);
        }

        expect($tuples['financial'])->toBe([
            ['a:amount', 'dec:2', '-0.10'],
            ['a:currency', 'str', 'EUR'],
            ['a:customer_id', 'int', '1234567890123'],
            ['a:due_on', 'date', '2026-02-28'],
            ['a:paid', 'bool', '0'],
            ['a:region', 'str', 'eu'],
            ['a:status', 'str', 'paid'],
            ['c:lines', 'json', '[{"quantity":3,"sku":"X"}]'],
        ])->and($tuples['identity'])->toBe([
            ['a:meta', 'json', '{"a":"é","z":[1,2.5,{"a":null,"b":true}]}'],
            ['a:number', 'str', 'N°7'],
            ['a:secret', 'str', 'ü'],
        ]);
    } finally {
        Carbon::setTestNow();
    }
});

/**
 * §10 items 26 and 28: datetimes and declared floats come back from every engine in its own
 * raw form (pgsql trims trailing fraction zeros, SQLite stores floats as REAL) and still
 * canonicalize to the same bytes.
 */
it('canonicalizes datetimes and declared floats to the same bytes on every engine', function (): void {
    $record = record(['happened_at' => '2026-10-02 18:30:00.500000', 'ratio' => 0.25]);
    $seal = app(DefinitionRegistry::class)->seal($record);
    $row = app(ReadBack::class)->row($record, $seal->readColumns()) ?? [];
    $message = app(DocumentBuilder::class)->build($record, $seal, $seal->fields, $row, 'default', 'k', Algorithm::HmacSha256, 1, null, CarbonImmutable::now());
    $tuples = array_column(array_map(static fn ($field): array => $field->tuple(), $message->fields), null, 0);

    expect($tuples['a:happened_at'])->toBe(['a:happened_at', 'dt', '2026-10-02T18:30:00.500000Z'])
        ->and($tuples['a:ratio'])->toBe(['a:ratio', 'flt:3', '0.250'])
        ->and(Sentinel::verify($record)->isIntact())->toBeTrue();
});

it('reads a pgsql timestamptz in any session time zone as the same instant', function (): void {
    DB::statement("set time zone 'America/New_York'");

    try {
        $raw = DB::selectOne("select '2026-10-02 18:30:00.25+00'::timestamptz as at")->at;

        expect($raw)->toBe('2026-10-02 14:30:00.25-04')
            ->and((new Normalizer)->normalize('a:at', SealType::datetime(), $raw)->tuple())->toBe(['a:at', 'dt', '2026-10-02T18:30:00.250000Z']);
    } finally {
        DB::statement("set time zone 'UTC'");
    }
})->skip(fn (): bool => DriverMatrix::driver() !== 'pgsql', 'timestamptz is a PostgreSQL type');
