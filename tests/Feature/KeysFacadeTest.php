<?php

declare(strict_types=1);

use PHPUnit\Framework\ExpectationFailedException;
use RoundlyConsulting\Sentinel\Actions\Keys\GenerateKeyAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;

it('runs the key API through the facade, the injected manager and the raw action alike', function (): void {
    $facade = Sentinel::generateKey(new GenerateKeyRequest('http', Algorithm::HmacSha256, 'via-facade'));
    $injected = app(SentinelManager::class)->generateKey(new GenerateKeyRequest('http', Algorithm::HmacSha256, 'via-di'));
    $action = app(GenerateKeyAction::class)->execute(new GenerateKeyRequest('http', Algorithm::HmacSha256, 'via-action'));

    expect([$facade->info->keyId, $injected->info->keyId, $action->info->keyId])->toBe(['via-facade', 'via-di', 'via-action'])
        ->and(app(SentinelManager::class))->toBe(app(SentinelManager::class))
        ->and(Sentinel::listKeys('http'))->toHaveCount(3)
        ->and(Sentinel::rotateKey(new RotateKeyRequest('http'))->previous?->keyId)->toBe('via-action')
        ->and(Sentinel::revokeKey(new RevokeKeyRequest('http', 'via-di', 'test'))->status)->toBe(KeyStatus::Revoked)
        ->and(Sentinel::retireKey('http', 'via-facade')->status)->toBe(KeyStatus::Retired);
});

it('resolves key actions through the container so a host override applies', function (): void {
    app()->bind(GenerateKeyAction::class, static fn (): never => throw new RuntimeException('overridden'));

    Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha256);
})->throws(RuntimeException::class, 'overridden');

it('records key changes under the fake — facade, accessor and injected manager — without storing anything', function (): void {
    $fake = Sentinel::fake();

    Sentinel::keys()->ring('http')->generate(Algorithm::Ed25519, 'faked');
    app(SentinelManager::class)->rotateKey(new RotateKeyRequest('default'));
    Sentinel::keys()->ring('http')->revoke('faked', 'test');
    Sentinel::keys()->ring('http')->retire('faked');

    expect(app(SentinelManager::class))->toBeInstanceOf(SentinelFake::class)
        ->and(Key::query()->count())->toBe(0)
        ->and($fake->recorded())->toHaveCount(4)
        ->and($fake->recorded('retireKey')[0]->arguments)->toBe(['http', 'faked']);

    $fake->assertKeyGenerated();
    $fake->assertKeyGenerated('http');
    $fake->assertKeyRotated();
    Sentinel::assertKeyRotated('default');
    Sentinel::assertKeyRevoked('faked');
});

it('keeps production validation in the fake', function (): void {
    Sentinel::fake();

    expect(fn () => Sentinel::keys()->ring('http')->generate(Algorithm::HmacSha512))->toThrow(AlgorithmNotAllowedException::class)
        ->and(fn () => Sentinel::generateKey(new GenerateKeyRequest('http', Algorithm::HmacSha256, '-bad')))->toThrow(KeyDriverException::class)
        ->and(fn () => Sentinel::rotateKey(new RotateKeyRequest('http', Algorithm::HmacSha384)))->toThrow(AlgorithmNotAllowedException::class)
        ->and(fn () => Sentinel::revokeKey(new RevokeKeyRequest('http', 'k', ' ')))->toThrow(KeyDriverException::class)
        ->and(fn () => Sentinel::retireKey('nope', 'k'))->toThrow(SealingMisconfiguredException::class)
        ->and(Sentinel::generateKey(new GenerateKeyRequest('http', Algorithm::HmacSha256, destination: KeyDestination::Config))->info->driver)->toBe('config');
});

it('passes assertNoKeyChanges on an untouched fake and fails it after a change', function (): void {
    $fake = Sentinel::fake();
    $fake->assertNoKeyChanges();

    Sentinel::keys()->ring('http')->retire('k');

    expect(fn () => $fake->assertNoKeyChanges())->toThrow(ExpectationFailedException::class, '1 were recorded');
});

it('fails each key assertion when nothing matches', function (Closure $assert, string $message): void {
    Sentinel::fake();
    Sentinel::keys()->ring('default')->generate(Algorithm::HmacSha256, destination: KeyDestination::Config);

    expect($assert)->toThrow(ExpectationFailedException::class, $message);
})->with([
    'generated in another ring' => [fn () => Sentinel::assertKeyGenerated('http'), 'in ring [http]'],
    'nothing rotated' => [fn () => Sentinel::assertKeyRotated(), 'Expected a key rotation'],
    'ring not rotated' => [fn () => Sentinel::assertKeyRotated('http'), 'ring [http] to be rotated'],
    'not revoked' => [fn () => Sentinel::assertKeyRevoked('k'), 'Expected key [k] to be revoked'],
]);

it('fails assertKeyGenerated when nothing was generated', function (): void {
    Sentinel::fake()->assertKeyGenerated();
})->throws(ExpectationFailedException::class, 'Expected a key to be generated');
