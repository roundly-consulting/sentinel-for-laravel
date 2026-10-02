<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

/**
 * Re-seal a model's rows with the current key (rotation, changed definitions, a format
 * upgrade). Only rows that verify intact or outdated are re-sealed; every other status is
 * skipped and reported — or acknowledged, when `acknowledgeReason` is given. Never launders.
 */
final readonly class ResealOptions
{
    /**
     * @param  class-string<Model>  $model
     */
    public function __construct(
        public string $model,
        public ?string $seal = null,
        public ?string $fromKeyId = null,
        public bool $onlyOutdated = false,
        public int $chunk = 500,
        public bool $dryRun = false,
        public ?string $acknowledgeReason = null,
        public ?Model $actor = null,
        public bool $upgradeFormat = false,
    ) {}
}
