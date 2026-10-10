<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

/**
 * A checkpoint that was just written, and where it was anchored.
 */
final readonly class CheckpointResult
{
    /**
     * @param  list<AnchorPublication>  $anchors  empty when the checkpoint was made inside a
     *                                            transaction (anchors get it after the commit)
     */
    public function __construct(
        public string $connection,
        public int $seq,
        public int $entries,
        public string $root,
        public array $anchors,
    ) {}
}
