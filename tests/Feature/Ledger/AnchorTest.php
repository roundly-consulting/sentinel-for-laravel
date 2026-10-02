<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use RoundlyConsulting\Sentinel\DataTransferObjects\AnchorPayload;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Events\AnchorPublishFailed;
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
