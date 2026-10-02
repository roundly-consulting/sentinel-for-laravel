<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;

/**
 * Audit reasons (acknowledgements, unseals, suspensions, baselines): trimmed, never empty,
 * bounded by `sentinel.sealing.reason_max_length`. Shared by the real manager and the fake.
 */
final class Reasons
{
    public static function normalize(?string $reason): string
    {
        $reason = trim((string) $reason);

        if ($reason === '') {
            throw AcknowledgementDeniedException::reason();
        }

        $maximum = Settings::reasonMaxLength();

        if (mb_strlen($reason) > $maximum) {
            throw AcknowledgementDeniedException::reasonTooLong($maximum);
        }

        return $reason;
    }
}
