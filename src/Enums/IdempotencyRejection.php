<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Enums;

use RoundlyConsulting\Enums\Helpers;

/**
 * Why an idempotent request was refused (the problem `code`), with its HTTP status
 * (draft-ietf-httpapi-idempotency-key-header-07 §2.7).
 */
enum IdempotencyRejection: string
{
    use Helpers;

    case Missing = 'idempotency_key_missing';
    case Invalid = 'invalid_idempotency_key';
    case Reused = 'idempotency_key_reused';
    case InProgress = 'idempotency_request_in_progress';
    case Unavailable = 'idempotent_response_unavailable';

    public function status(): int
    {
        return match ($this) {
            self::Missing, self::Invalid => 400,
            self::Reused => 422,
            self::InProgress, self::Unavailable => 409,
        };
    }
}
