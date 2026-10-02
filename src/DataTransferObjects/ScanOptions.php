<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Closure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * A chunked verification scan (`sentinel:verify`): which models, one seal or every seal (null),
 * at most `limit` rows in total, at most `maxFindings` failures kept in the report. `where`
 * narrows the scan of one model — a closure receives the model's query (global scopes off, as
 * for the whole-table scan) or a builder of that model is used as is; it filters, never
 * orders. `progress` is called after each chunk with the rows processed so far.
 */
final readonly class ScanOptions
{
    /**
     * @param  list<class-string<Model>>  $models
     * @param  (Closure(Builder<Model>): mixed)|Builder<Model>|null  $where
     * @param  (Closure(int): void)|null  $progress
     */
    public function __construct(
        public array $models,
        public ?string $seal = null,
        public int $chunk = 500,
        public bool $checkLedger = true,
        public ?int $limit = null,
        public int $maxFindings = 1000,
        public bool $checkSchema = false,
        public Closure|Builder|null $where = null,
        public ?Closure $progress = null,
    ) {}
}
