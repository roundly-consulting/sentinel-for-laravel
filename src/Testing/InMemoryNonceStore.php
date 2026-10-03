<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Contracts\NonceStore;
use RoundlyConsulting\Sentinel\Support\CountsExpired;

/**
 * The fake's nonce store: the real rules (purpose, subject, expiry, use once, remember until)
 * over a PHP array.
 */
final class InMemoryNonceStore implements CountsExpired, NonceStore
{
    /** @var array<string, array{subject: string|null, expires: CarbonImmutable, consumed: bool}> */
    private array $issued = [];

    /** @var array<string, CarbonImmutable> */
    private array $seen = [];

    public function issue(string $purpose, string $digest, CarbonImmutable $expiresAt, ?Model $subject): void
    {
        $this->issued["{$purpose}\0{$digest}"] = ['subject' => self::subject($subject), 'expires' => $expiresAt, 'consumed' => false];
    }

    public function consume(string $purpose, string $digest, CarbonImmutable $now, ?Model $subject): bool
    {
        $nonce = $this->issued["{$purpose}\0{$digest}"] ?? null;

        if ($nonce === null || $nonce['consumed'] || $nonce['expires']->lte($now) || $nonce['subject'] !== self::subject($subject)) {
            return false;
        }

        $this->issued["{$purpose}\0{$digest}"]['consumed'] = true;

        return true;
    }

    public function remember(string $purpose, string $digest, CarbonImmutable $until, CarbonImmutable $now): bool
    {
        $seen = $this->seen["{$purpose}\0{$digest}"] ?? null;

        if ($seen !== null && $seen->gt($now)) {
            return false;
        }

        $this->seen["{$purpose}\0{$digest}"] = $until;

        return true;
    }

    public function countExpired(CarbonImmutable $now): int
    {
        return count(array_filter($this->issued, static fn (array $nonce): bool => $nonce['expires']->lte($now)))
            + count(array_filter($this->seen, static fn (CarbonImmutable $until): bool => $until->lte($now)));
    }

    public function prune(CarbonImmutable $now): int
    {
        $before = count($this->issued) + count($this->seen);
        $this->issued = array_filter($this->issued, static fn (array $nonce): bool => $nonce['expires']->gt($now));
        $this->seen = array_filter($this->seen, static fn (CarbonImmutable $until): bool => $until->gt($now));

        return $before - count($this->issued) - count($this->seen);
    }

    private static function subject(?Model $subject): ?string
    {
        return $subject === null ? null : $subject->getMorphClass().':'.$subject->getKey();
    }
}
