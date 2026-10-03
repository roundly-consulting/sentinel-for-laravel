<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * What verify-on-retrieve does when a model is not intact. Both report the finding
 * (`TamperDetected` and a warning log line, like every verification); `Throw` also refuses to
 * load the model.
 */
enum Reaction: string
{
    use Helpers;

    case Throw = 'throw';
    case Report = 'report';
}
