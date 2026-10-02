<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use RoundlyConsulting\Sentinel\Canonical\FieldTagger;
use RoundlyConsulting\Sentinel\Engine\DocumentBuilder;
use RoundlyConsulting\Sentinel\Engine\LedgerWriter;
use RoundlyConsulting\Sentinel\Engine\ReadBack;
use RoundlyConsulting\Sentinel\Engine\Sealer;
use RoundlyConsulting\Sentinel\Engine\Verifier;
use RoundlyConsulting\Sentinel\Events\ModelSealed;
use RoundlyConsulting\Sentinel\Events\TamperDetected;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Keys\KeyCache;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\SealingScope;

/**
 * §10 item 35 (keys part): decrypted keys live in a scoped cache that Laravel resets between
 * Octane requests and queued jobs; the singletons hold no request state.
 */
it('gives every request (or job) a fresh key cache', function (): void {
    $first = app(KeyCache::class);
    $store = app(KeyStoreManager::class)->ring('default');

    expect(app(KeyCache::class))->toBe($first)
        ->and(app(KeyStoreManager::class)->ring('default'))->toBe($store);

    // What Octane and the queue worker do between units of work.
    app()->forgetScopedInstances();

    expect(app(KeyCache::class))->not->toBe($first)
        ->and(app(KeyStoreManager::class)->ring('default'))->not->toBe($store)
        ->and(app(KeyStoreManager::class))->toBe(app(KeyStoreManager::class))
        ->and(app(SentinelManager::class))->toBe(app(SentinelManager::class));
});

it('sees a config change after the request boundary, never a stale key', function (): void {
    expect(app(KeyStoreManager::class)->signingKey('default')->keyId)->toBe('test-default');

    config()->set('sentinel.keys.rings.default.key_id', 'rotated');
    app()->forgetScopedInstances();

    expect(app(KeyStoreManager::class)->signingKey('default')->keyId)->toBe('rotated');
});

it('holds no key cache inside the singleton manager', function (): void {
    $properties = array_map(
        static fn (ReflectionProperty $property): string => (string) $property->getType(),
        (new ReflectionClass(KeyStoreManager::class))->getProperties(),
    );

    expect($properties)->not->toContain(KeyCache::class);
});

/**
 * I-5: the stateless engine services are scoped — one instance per request / job, never
 * process-wide — and their scoped collaborators are replaced with them.
 */
it('scopes the stateless engine services to the request or job', function (string $service): void {
    $first = app($service);

    expect(app($service))->toBe($first);

    app()->forgetScopedInstances();

    expect(app($service))->not->toBe($first);
})->with([Verifier::class, Sealer::class, DocumentBuilder::class, LedgerWriter::class, ReadBack::class, FieldTagger::class, Signers::class]);

it('keeps no decrypted key and no stale scope in the scoped engine services', function (): void {
    invoice();
    $builder = app(DocumentBuilder::class);
    $scope = (new ReflectionProperty(DocumentBuilder::class, 'scope'))->getValue($builder);

    expect($scope)->toBe(app(SealingScope::class));

    app()->forgetScopedInstances();

    expect((new ReflectionProperty(DocumentBuilder::class, 'scope'))->getValue(app(DocumentBuilder::class)))->toBe(app(SealingScope::class))
        ->not->toBe($scope);

    foreach ([Verifier::class, Sealer::class, DocumentBuilder::class, LedgerWriter::class, ReadBack::class, FieldTagger::class, Signers::class] as $service) {
        $reflection = new ReflectionClass($service);
        $types = array_map(static fn (ReflectionProperty $property): string => (string) $property->getType(), $reflection->getProperties());

        expect($reflection->isReadOnly())->toBeTrue("{$service} is not readonly")
            ->and($types)->not->toContain(KeyCache::class)
            ->and($types)->not->toContain(SealingKey::class)
            ->and($types)->not->toContain(KeyMaterial::class);
    }
});

it('reports to an event fake or log spy installed after the scoped engine was built', function (): void {
    $invoice = invoice();
    Sentinel::verify($invoice);
    DB::table('invoices')->where('id', $invoice->id)->update(['amount' => '0.01']);

    Event::fake([TamperDetected::class, ModelSealed::class]);
    $log = Log::spy();
    $log->shouldReceive('channel')->andReturn($log);

    Sentinel::verify($invoice);
    Sentinel::seal(invoice());

    Event::assertDispatched(TamperDetected::class);
    Event::assertDispatched(ModelSealed::class);
    $log->shouldHaveReceived('warning')->once();
});
