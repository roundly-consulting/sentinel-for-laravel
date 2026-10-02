<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use RoundlyConsulting\Sentinel\Actions\ExampleSentinelAction;

/**
 * REPLACE ME — the input of {@see ExampleSentinelAction}.
 *
 * Actions take a DTO, never a shape array. Rename this alongside the action it feeds.
 */
final readonly class ExampleSentinelData
{
    public function __construct(
        public string $name,
    ) {}
}
