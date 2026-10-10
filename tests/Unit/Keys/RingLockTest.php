<?php

declare(strict_types=1);

use Illuminate\Database\Connection;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Keys\RingLock;

/**
 * The ring lock's statements per engine, on a connection that records them with the
 * transaction level they ran at. Whether the lock holds is proven on the real engines
 * (tests/RealEngine/KeyRotationRaceTest.php); this pins what each engine is sent.
 */
final class LockRecordingConnection extends Connection
{
    /** @var list<array{0: string, 1: array<int, mixed>, 2: int}> */
    public array $log = [];

    public function __construct(private readonly string $engine, private readonly mixed $acquired = 1)
    {
        parent::__construct(new PDO('sqlite::memory:'), 'app');
    }

    public function getDriverName(): string
    {
        return $this->engine;
    }

    public function select($query, $bindings = [], $useReadPdo = true, array $fetchUsing = []): array
    {
        $this->log[] = [$query, $bindings, $this->transactionLevel()];

        return $this->acquired === 'no row' ? [] : [(object) ['acquired' => $this->acquired]];
    }

    public function statement($query, $bindings = []): bool
    {
        $this->log[] = [$query, $bindings, $this->transactionLevel()];

        return true;
    }

    public function work(): Closure
    {
        return function (): string {
            $this->log[] = ['work', [], $this->transactionLevel()];

            return 'done';
        };
    }
}

const RING_GET_LOCK = 'select get_lock(?, @@innodb_lock_wait_timeout) as acquired';
const RING_RELEASE_LOCK = 'select release_lock(?)';
const RING_ADVISORY_LOCK = 'select pg_advisory_xact_lock(cast(? as bigint))';
const RING_READ_COMMITTED = 'set transaction isolation level read committed';

it('takes a transaction-level advisory lock first on PostgreSQL, at READ COMMITTED', function (): void {
    $connection = new LockRecordingConnection('pgsql');

    expect(RingLock::transaction($connection, 'http', $connection->work(), 3))->toBe('done')
        ->and($connection->log)->toBe([
            [RING_READ_COMMITTED, [], 1],
            [RING_ADVISORY_LOCK, [RingLock::advisoryKey('http')], 1],
            ['work', [], 1],
        ]);
});

it('leaves the isolation level of an enclosing transaction alone on PostgreSQL', function (): void {
    $connection = new LockRecordingConnection('pgsql');

    $connection->transaction(static fn (): string => RingLock::transaction($connection, 'http', $connection->work()));

    expect($connection->log)->toBe([
        [RING_ADVISORY_LOCK, [RingLock::advisoryKey('http')], 2],
        ['work', [], 2],
    ]);
});

it('holds a named lock around the whole transaction on MySQL and MariaDB', function (string $engine): void {
    $connection = new LockRecordingConnection($engine);
    $name = RingLock::lockName($connection, 'http');

    expect(RingLock::transaction($connection, 'http', $connection->work(), 3))->toBe('done')
        ->and($connection->log)->toBe([
            [RING_GET_LOCK, [$name], 0],
            ['work', [], 1],
            [RING_RELEASE_LOCK, [$name], 0],
        ]);
})->with(['mysql', 'mariadb']);

it('releases the named lock when the rotation fails', function (): void {
    $connection = new LockRecordingConnection('mysql');

    expect(fn () => RingLock::transaction($connection, 'http', static fn (): never => throw new RuntimeException('boom')))
        ->toThrow(RuntimeException::class, 'boom')
        ->and(array_column($connection->log, 0))->toBe([RING_GET_LOCK, RING_RELEASE_LOCK]);
});

it('refuses to rotate while another rotation holds the named lock past the wait timeout', function (mixed $acquired): void {
    $connection = new LockRecordingConnection('mysql', $acquired);

    expect(fn () => RingLock::transaction($connection, 'http', $connection->work()))
        ->toThrow(KeyDriverException::class, 'Another rotation of key ring [http] is still running')
        ->and(array_column($connection->log, 0))->toBe([RING_GET_LOCK]);
})->with([
    'timed out' => [0],
    'interrupted' => [null],
    'no answer' => ['no row'],
]);

it('takes no lock on SQLite, which allows one writer at a time', function (): void {
    $connection = new LockRecordingConnection('sqlite');

    expect(RingLock::transaction($connection, 'http', $connection->work()))->toBe('done')
        ->and($connection->log)->toBe([['work', [], 1]]);
});

it('keeps rings — and on MySQL databases — apart in the lock identity', function (): void {
    $app = new LockRecordingConnection('mysql');
    $other = new class extends Connection
    {
        public function __construct()
        {
            parent::__construct(new PDO('sqlite::memory:'), 'other-app');
        }
    };

    expect(RingLock::advisoryKey('http'))->not->toBe(RingLock::advisoryKey('default'))
        ->and(RingLock::advisoryKey('http') >> 32)->toBe(0x53454E54)
        ->and(RingLock::advisoryKey('http'))->toBeGreaterThan(0)
        ->and(RingLock::lockName($app, 'http'))->not->toBe(RingLock::lockName($app, 'default'))
        ->and(RingLock::lockName($app, 'http'))->not->toBe(RingLock::lockName($other, 'http'))
        ->and(strlen(RingLock::lockName($app, str_repeat('r', 64))))->toBeLessThanOrEqual(64);
});
