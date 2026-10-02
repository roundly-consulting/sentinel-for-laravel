<?php

declare(strict_types=1);

use Carbon\CarbonImmutable;
use RoundlyConsulting\Sentinel\Casts\UtcDateTime;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Models\Key;

it('stores any zone as a UTC microsecond string', function (): void {
    $cast = new UtcDateTime;

    expect($cast->set(new Key, 'activates_at', CarbonImmutable::parse('2026-10-02 20:30:00.25', 'Europe/Bratislava'), []))
        ->toBe('2026-10-02 18:30:00.250000')
        ->and($cast->set(new Key, 'activates_at', CarbonImmutable::parse('2026-10-02 14:30:00', 'America/New_York'), []))
        ->toBe('2026-10-02 18:30:00.000000')
        ->and($cast->set(new Key, 'activates_at', '2026-10-02 18:30:00', []))->toBe('2026-10-02 18:30:00.000000')
        ->and($cast->set(new Key, 'activates_at', null, []))->toBeNull();
});

it('reads every engine representation back as UTC', function (string $stored, string $expected): void {
    $value = (new UtcDateTime)->get(new Key, 'activates_at', $stored, []);

    expect($value?->getTimezone()->getName())->toBe('UTC')
        ->and($value?->format('Y-m-d H:i:s.u'))->toBe($expected);
})->with([
    'sqlite / mysql datetime(6)' => ['2026-10-02 18:30:00.123456', '2026-10-02 18:30:00.123456'],
    'pgsql trimmed fraction' => ['2026-10-02 18:30:00.5', '2026-10-02 18:30:00.500000'],
    'no fraction' => ['2026-10-02 18:30:00', '2026-10-02 18:30:00.000000'],
]);

it('passes nulls and datetimes through and refuses anything else', function (): void {
    $cast = new UtcDateTime;

    expect($cast->get(new Key, 'x', null, []))->toBeNull()
        ->and($cast->get(new Key, 'x', CarbonImmutable::parse('2026-10-02 20:30', 'Europe/Bratislava'), [])?->format('H:i'))->toBe('18:30')
        ->and(fn () => $cast->get(new Key, 'revoked_at', 'yesterday', []))->toThrow(CorruptRecordException::class, 'revoked_at')
        ->and(fn () => $cast->set(new Key, 'revoked_at', 12345, []))->toThrow(CorruptRecordException::class);
});

it('keeps timestamps UTC while the process runs in another zone', function (): void {
    expect(date_default_timezone_get())->toBe('Europe/Bratislava');

    $key = Key::factory()->create();

    expect($key->getRawOriginal('created_at'))->toBe($key->created_at?->utc()->format('Y-m-d H:i:s.u'))
        ->and($key->created_at?->getTimezone()->getName())->toBe('UTC');
});
