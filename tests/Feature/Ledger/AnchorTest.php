<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPublication;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Events\AnchorPublishFailed;
use RoundlyConsulting\Sentinel\Exceptions\AnchorPublishException;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Ledger\AnchorCodec;
use RoundlyConsulting\Sentinel\Ledger\AnchorManager;
use RoundlyConsulting\Sentinel\Models\Checkpoint;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Tests\Fixtures\Anchors\MemoryAnchor;

function memoryAnchor(): MemoryAnchor
{
    return MemoryAnchor::install();
}

/**
 * @return list<string>
 */
function anchorFindings(?AnchorPayload $manual = null): array
{
    return array_map(
        static fn ($finding): string => $finding->kind->value.':'.$finding->detail,
        Sentinel::verifyLedger(new LedgerVerifyOptions(entities: false, manualAnchor: $manual))->findings,
    );
}

/**
 * §10 item 38: anchors keep a copy of the newest checkpoint outside the database.
 */
it('publishes every checkpoint to the cache, filesystem and log anchors', function (): void {
    Storage::fake('local');
    $log = Log::spy();
    $log->shouldReceive('channel')->andReturn($log);
    config()->set('sentinel.ledger.anchors', 'cache,filesystem,log');
    invoice();

    $result = Sentinel::checkpoint();
    $connection = DB::getDefaultConnection();

    expect(array_map(static fn ($publication): string => $publication->anchor.':'.($publication->published ? 'ok' : 'failed'), $result?->anchors ?? []))->toBe(['cache:ok', 'filesystem:ok', 'log:ok'])
        ->and(Sentinel::ledger()->anchors())->toBe(['cache', 'filesystem', 'log'])
        ->and(AnchorCodec::decode((string) Cache::get("sentinel:ledger:anchor:{$connection}"))->seq)->toBe(1)
        ->and(Storage::disk('local')->exists("sentinel/anchors/{$connection}/1.json"))->toBeTrue()
        ->and(AnchorCodec::decode((string) Storage::disk('local')->get("sentinel/anchors/{$connection}/latest.json"))->root)->toBe($result?->root)
        ->and(app(AnchorManager::class)->build('log')->latest($connection))->toBeNull()
        ->and(Sentinel::verifyLedger()->anchorsChecked)->toBe(2);

    $log->shouldHaveReceived('info')->withArgs(static fn (string $message, array $context): bool => $message === 'sentinel.anchor' && $context['seq'] === '1');
});

it('detects a rollback of the whole database past the anchored checkpoint (§3.2 #9, #10)', function (): void {
    memoryAnchor();
    invoice();
    Sentinel::checkpoint();
    invoice();
    Sentinel::checkpoint();

    // Restore an older snapshot: the newest checkpoint and its entries vanish together.
    DB::table('sentinel_seals')->update(['ledger_entry_id' => null]);
    $last = Checkpoint::query()->where('seq', 2)->value('id');
    DB::table('sentinel_ledger')->where('checkpoint_id', $last)->delete();
    DB::table('sentinel_checkpoints')->where('id', $last)->delete();

    expect(anchorFindings())->toContain('anchor_ahead:anchor [memory] holds seq 2, the database 1');
});

/**
 * Chat review C-1: after a restore, the next checkpoint must not overwrite the evidence.
 */
it('never overwrites an anchor that is ahead of a restored database', function (): void {
    Storage::fake('local');
    Event::fake([AnchorPublishFailed::class]);
    config()->set('sentinel.ledger.anchors', 'cache,filesystem');
    $connection = DB::getDefaultConnection();
    $disk = Storage::disk('local');

    foreach (range(1, 3) as $ignored) {
        invoice();
        Sentinel::checkpoint();
    }

    $two = (string) $disk->get("sentinel/anchors/{$connection}/2.json");
    $outcomes = static fn (?CheckpointResult $result): array => array_map(
        static fn ($publication): string => $publication->anchor.':'.($publication->published ? 'ok' : 'refused'),
        $result?->anchors ?? [],
    );

    // Restore a snapshot taken at seq 1: the newer checkpoints and their entries vanish together.
    DB::table('sentinel_seals')->update(['ledger_entry_id' => null]);
    $newer = Checkpoint::query()->where('seq', '>', 1)->pluck('id');
    DB::table('sentinel_ledger')->whereIn('checkpoint_id', $newer)->delete();
    DB::table('sentinel_checkpoints')->whereIn('id', $newer)->delete();

    invoice();
    $second = Sentinel::checkpoint();

    expect($second?->seq)->toBe(2)
        ->and($outcomes($second))->toBe(['cache:refused', 'filesystem:refused'])
        ->and($second?->anchors[0]->error)->toContain('anchor [cache] holds seq 3, the database 2')
        ->and(AnchorCodec::decode((string) Cache::get("sentinel:ledger:anchor:{$connection}"))->seq)->toBe(3)
        ->and(AnchorCodec::decode((string) $disk->get("sentinel/anchors/{$connection}/latest.json"))->seq)->toBe(3)
        ->and($disk->get("sentinel/anchors/{$connection}/2.json"))->toBe($two)
        ->and(anchorFindings())->toContain('anchor_ahead:anchor [cache] holds seq 3, the database 2', 'anchor_ahead:anchor [filesystem] holds seq 3, the database 2');

    // The database catches up with another history: the anchored seq 3 differs, so neither the
    // new seq 3 nor anything after it replaces it.
    invoice();
    $third = Sentinel::checkpoint();
    invoice();
    $fourth = Sentinel::checkpoint();

    expect($outcomes($third))->toBe(['cache:refused', 'filesystem:refused'])
        ->and($outcomes($fourth))->toBe(['cache:refused', 'filesystem:refused'])
        ->and(AnchorCodec::decode((string) $disk->get("sentinel/anchors/{$connection}/latest.json"))->seq)->toBe(3)
        ->and($disk->exists("sentinel/anchors/{$connection}/4.json"))->toBeFalse()
        ->and(anchorFindings())->toContain('anchor_mismatch:anchor [cache]: the checkpoint root differs');

    Event::assertDispatchedTimes(AnchorPublishFailed::class, 6);
});

it('treats an anchor already holding this checkpoint or a newer one of the same chain as published', function (): void {
    $anchor = memoryAnchor();
    invoice();
    Sentinel::checkpoint();
    invoice();
    Sentinel::checkpoint();
    $connection = DB::getDefaultConnection();
    $held = $anchor->stored[$connection];
    $payload = static fn (int $seq): AnchorPayload => AnchorCodec::fromCheckpoint(Checkpoint::query()->where('seq', $seq)->firstOrFail(), $connection)
        ?? throw new RuntimeException('no payload');

    Event::fake([AnchorPublishFailed::class]);

    expect(app(AnchorManager::class)->publish($payload(1)))->toEqual([new AnchorPublication('memory', true)])
        ->and(app(AnchorManager::class)->publish($payload(2)))->toEqual([new AnchorPublication('memory', true)])
        ->and(app(AnchorManager::class)->publish($payload(1), onlyLagging: true))->toBe([])
        ->and($anchor->stored[$connection])->toBe($held);

    Event::assertNotDispatched(AnchorPublishFailed::class);
});

/**
 * Chat review C-3: Laravel's disks (`throw` false) and some cache stores report a failed
 * write by returning false, not by throwing.
 */
it('reports an anchor write that its store refused as a failed publication', function (): void {
    Event::fake([AnchorPublishFailed::class]);
    $log = Log::spy();
    $log->shouldReceive('channel')->andReturn($log);
    $root = sys_get_temp_dir().'/sentinel-anchor-'.bin2hex(random_bytes(6));
    $connection = DB::getDefaultConnection();
    mkdir("{$root}/sentinel/anchors/{$connection}", 0755, true);
    chmod("{$root}/sentinel/anchors/{$connection}", 0555);
    config()->set('filesystems.disks.read-only', ['driver' => 'local', 'root' => $root, 'throw' => false]);
    config()->set('cache.stores.nowhere', ['driver' => 'null']);
    config()->set('sentinel.ledger.anchor_drivers.filesystem.disk', 'read-only');
    config()->set('sentinel.ledger.anchor_drivers.cache.store', 'nowhere');
    config()->set('sentinel.ledger.anchors', 'cache,filesystem');
    invoice();

    try {
        $result = Sentinel::checkpoint();
    } finally {
        chmod("{$root}/sentinel/anchors/{$connection}", 0755);
        File::deleteDirectory($root);
    }

    expect(array_map(static fn ($publication): string => $publication->anchor.':'.($publication->published ? 'ok' : 'failed'), $result?->anchors ?? []))->toBe(['cache:failed', 'filesystem:failed'])
        ->and($result?->anchors[0]->error)->toContain('did not write')
        ->and($result?->anchors[1]->error)->toContain('did not write');

    Event::assertDispatchedTimes(AnchorPublishFailed::class, 2);
    $log->shouldHaveReceived('warning')->twice();
});

it('writes each numbered filesystem anchor file once', function (): void {
    Storage::fake('local');
    $anchor = app(AnchorManager::class)->build('filesystem');
    $payload = new AnchorPayload('main', 1, 'root', Clock::now(), 'default', 'kid', Algorithm::HmacSha256, 'mac');

    $anchor->publish($payload);
    Storage::disk('local')->delete('sentinel/anchors/main/latest.json');
    $anchor->publish($payload);

    expect(fn () => $anchor->publish(new AnchorPayload('main', 1, 'other-root', Clock::now(), 'default', 'kid', Algorithm::HmacSha256, 'mac')))
        ->toThrow(AnchorPublishException::class, 'already holds another seq 1')
        ->and(AnchorCodec::decode((string) Storage::disk('local')->get('sentinel/anchors/main/1.json'))->root)->toBe('root')
        ->and(AnchorCodec::decode((string) Storage::disk('local')->get('sentinel/anchors/main/latest.json'))->root)->toBe('root');

    // The numbered file is in place, but latest.json cannot be written (C-3).
    Storage::disk('local')->delete('sentinel/anchors/main/latest.json');
    Storage::disk('local')->makeDirectory('sentinel/anchors/main/latest.json');

    expect(fn () => $anchor->publish($payload))->toThrow(AnchorPublishException::class, 'did not write [sentinel/anchors/main/latest.json]');
});

it('reports a rewritten, forged or unreachable anchor', function (Closure $tamper, string $expected): void {
    $anchor = memoryAnchor();
    invoice();
    Sentinel::checkpoint();
    $connection = DB::getDefaultConnection();
    $payload = AnchorCodec::decode($anchor->stored[$connection]);

    $tamper($anchor, $payload, $connection);

    expect(implode("\n", anchorFindings()))->toContain($expected);
})->with([
    'another root' => [static fn (MemoryAnchor $a, AnchorPayload $p, string $c) => $a->stored[$c] = AnchorCodec::encode(new AnchorPayload($c, 1, str_repeat('x', 43), $p->at, $p->ring, $p->keyId, $p->algorithm, $p->mac)), 'anchor_mismatch'],
    'a forged MAC' => [static fn (MemoryAnchor $a, AnchorPayload $p, string $c) => $a->stored[$c] = AnchorCodec::encode(new AnchorPayload($c, 1, $p->root, $p->at, $p->ring, $p->keyId, $p->algorithm, str_repeat('m', 43))), 'anchor_invalid:anchor [memory]: mac'],
    'an unknown key' => [static fn (MemoryAnchor $a, AnchorPayload $p, string $c) => $a->stored[$c] = AnchorCodec::encode(new AnchorPayload($c, 9, $p->root, $p->at, $p->ring, 'forger', $p->algorithm, $p->mac)), 'anchor_invalid:anchor [memory]: not_found'],
    'another algorithm' => [static fn (MemoryAnchor $a, AnchorPayload $p, string $c) => $a->stored[$c] = AnchorCodec::encode(new AnchorPayload($c, 1, $p->root, $p->at, $p->ring, $p->keyId, Algorithm::HmacSha512, $p->mac)), 'anchor_invalid:anchor [memory]: algorithm_mismatch'],
    'garbage' => [static fn (MemoryAnchor $a, AnchorPayload $p, string $c) => $a->stored[$c] = '{"v":"other"}', 'anchor_invalid:anchor [memory]: The anchor payload'],
    'an outage' => [static fn (MemoryAnchor $a) => $a->broken = true, 'anchor_unreachable:anchor [memory]: RuntimeException'],
]);

it('reports a failed publication and republishes on the next run', function (): void {
    Event::fake([AnchorPublishFailed::class]);
    $anchor = memoryAnchor();
    invoice();
    Sentinel::checkpoint();
    $anchor->broken = true;
    invoice();

    $failed = Sentinel::checkpoint();

    expect($failed?->anchors[0]->published)->toBeFalse()
        ->and($failed?->anchors[0]->error)->toContain('anchor offline');

    Event::assertDispatched(AnchorPublishFailed::class, static fn (AnchorPublishFailed $event): bool => $event->seq === 2 && $event->anchor === 'memory');

    $anchor->broken = false;

    expect(Sentinel::checkpoint())->toBeNull()
        ->and(AnchorCodec::decode($anchor->stored[DB::getDefaultConnection()])->seq)->toBe(2);
});

/**
 * Chat review V-1: an anchor that missed the first checkpoint holds nothing, not "older".
 */
it('republishes to an anchor that holds nothing, but never re-sends to a write-only one', function (): void {
    $log = Log::spy();
    $log->shouldReceive('channel')->andReturn($log);
    $anchor = memoryAnchor();
    config()->set('sentinel.ledger.anchors', 'memory,log');
    $anchor->broken = true;
    invoice();

    $first = Sentinel::checkpoint();
    $anchor->broken = false;

    expect($first?->anchors[0]->published)->toBeFalse()
        ->and($anchor->stored)->toBe([])
        ->and(Sentinel::checkpoint())->toBeNull()
        ->and(AnchorCodec::decode($anchor->stored[DB::getDefaultConnection()])->seq)->toBe(1)
        ->and(Sentinel::checkpoint())->toBeNull();

    $log->shouldHaveReceived('info')->once();
});

it('compares a payload copied out of a write-only anchor', function (): void {
    invoice();
    Sentinel::checkpoint();
    $checkpoint = Checkpoint::query()->firstOrFail();
    $payload = AnchorCodec::fromCheckpoint($checkpoint, DB::getDefaultConnection());

    expect(anchorFindings($payload))->toBe([])
        ->and(anchorFindings(new AnchorPayload(DB::getDefaultConnection(), 7, 'r', Clock::now(), 'default', 'test-default', Algorithm::HmacSha256, 'm')))->toBe(['anchor_ahead:anchor [manual] holds seq 7, the database 1'])
        ->and(anchorFindings(new AnchorPayload('elsewhere', 1, 'r', Clock::now(), 'default', 'test-default', Algorithm::HmacSha256, 'm')))->toBe(['anchor_invalid:manual anchor names an unverified connection']);
});

it('round-trips anchor payloads strictly', function (): void {
    $payload = new AnchorPayload('main', 3, 'root', Clock::now(), 'default', 'kid', Algorithm::Ed25519, 'mac');
    $decoded = AnchorCodec::decode(AnchorCodec::encode($payload));

    expect($decoded->seq)->toBe(3)
        ->and($decoded->algorithm)->toBe(Algorithm::Ed25519)
        ->and($decoded->at->format('Y-m-d H:i:s.u'))->toBe($payload->at->format('Y-m-d H:i:s.u'))
        ->and(AnchorCodec::toArray($payload)['v'])->toBe('sentinel.anchor/1');

    foreach (['', '[]', '"x"', '{"v":"sentinel.anchor/1"}', str_replace('"seq":"3"', '"seq":"03"', AnchorCodec::encode($payload)), str_replace('Z"', '"', AnchorCodec::encode($payload))] as $broken) {
        expect(fn () => AnchorCodec::decode($broken))->toThrow(CorruptRecordException::class);
    }
});

it('refuses unknown anchor drivers and invalid names', function (): void {
    config()->set('sentinel.ledger.anchors', 'nope');

    invoice();

    expect(fn () => app(AnchorManager::class)->build('nope'))->toThrow(InvalidSentinelConfigurationException::class, 'unknown anchor driver')
        ->and(fn () => Sentinel::checkpoint())->toThrow(InvalidSentinelConfigurationException::class)
        ->and(Checkpoint::query()->count())->toBe(0);

    config()->set('sentinel.ledger.anchors', 'Not Valid');

    expect(fn () => Sentinel::ledger()->anchors())->toThrow(InvalidSentinelConfigurationException::class);

    Sentinel::extendAnchor('weird', static fn (): string => 'not an anchor');

    expect(fn () => app(AnchorManager::class)->build('weird'))->toThrow(InvalidSentinelConfigurationException::class);
});

it('keeps a hostile connection name a single safe path segment', function (): void {
    Storage::fake('local');
    $anchor = app(AnchorManager::class)->build('filesystem');
    $payload = new AnchorPayload('../../etc', 1, 'root', Clock::now(), 'default', 'kid', Algorithm::HmacSha256, 'mac');

    $anchor->publish($payload);

    expect(Storage::disk('local')->allFiles())->each->toStartWith('sentinel/anchors/conn-')
        ->and($anchor->latest('../../etc')?->seq)->toBe(1)
        ->and($anchor->latest('other'))->toBeNull();
});
