<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

/**
 * A chunked verification scan (`sentinel:verify`): which models, one seal or every seal (null),
 * at most `limit` rows in total, at most `maxFindings` failures kept in the report.
 */
final readonly class ScanOptions
{
    /**
     * @param  list<class-string<Model>>  $models
     */
    public function __construct(
        public array $models,
        public ?string $seal = null,
        public int $chunk = 500,
        public bool $checkLedger = true,
        public ?int $limit = null,
        public int $maxFindings = 1000,
        public bool $checkSchema = false,
    ) {}
}
