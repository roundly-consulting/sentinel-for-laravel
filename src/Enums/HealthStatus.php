<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * The outcome of one installation check (`Sentinel::check()`, `sentinel:check`).
 */
enum HealthStatus: string
{
    use Helpers;

    case Ok = 'ok';
    case Warning = 'warning';
    case Failure = 'failure';
}
