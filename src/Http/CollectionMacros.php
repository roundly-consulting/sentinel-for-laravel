<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http;

use Closure;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationReport;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * `$invoices->verifySeals(?string $seal = null)` on Eloquent collections. Eager-loaded seal
 * rows (`->withSeals()`) are reused, so a page of models verifies without a query per row.
 *
 * @internal
 */
final class CollectionMacros
{
    public static function register(): void
    {
        if (Collection::hasMacro('verifySeals')) {
            return;
        }

        self::define(function (?string $seal = null): VerificationReport {
            return app(SentinelManager::class)->verifyManyIn(VerificationContext::Collection, $this->all(), $seal);
        });
    }

    /**
     * @param-closure-this Collection<array-key, Model> $macro
     */
    private static function define(Closure $macro): void
    {
        Collection::macro('verifySeals', $macro);
    }
}
