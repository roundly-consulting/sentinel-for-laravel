<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use RoundlyConsulting\Sentinel\Models\IdempotencyKey;
use RoundlyConsulting\Sentinel\Models\Nonce;

it('prunes expired idempotency keys and nonces, both unless one is named', function (): void {
    IdempotencyKey::factory()->expired()->create();
    IdempotencyKey::factory()->create();
    Nonce::factory()->expired()->create();

    expect(Artisan::call('sentinel:prune', ['--idempotency' => true]))->toBe(0)
        ->and(Artisan::output())->toContain('Deleted idempotency keys')
        ->and(IdempotencyKey::query()->count())->toBe(1)
        ->and(Nonce::query()->count())->toBe(1)
        ->and(Artisan::call('sentinel:prune'))->toBe(0)
        ->and(Nonce::query()->count())->toBe(0);
});

it('reports a misconfigured store', function (): void {
    config()->set('sentinel.nonces.store', 'Not Valid');

    expect(Artisan::call('sentinel:prune'))->toBe(1);
});
