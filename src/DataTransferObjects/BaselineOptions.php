<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

/**
 * Seal rows that were never sealed (adoption): only rows with no seal row **and** no ledger
 * history; rows whose history shows a seal that went missing are reported instead.
 */
final readonly class BaselineOptions
{
    /**
     * @param  class-string<Model>  $model
     */
    public function __construct(
        public string $model,
        public ?string $seal,
        public string $reason,
        public int $chunk = 500,
        public ?Model $actor = null,
    ) {}
}
