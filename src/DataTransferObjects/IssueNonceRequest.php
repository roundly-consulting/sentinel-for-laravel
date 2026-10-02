<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\DataTransferObjects;

use Illuminate\Database\Eloquent\Model;

/**
 * Issue a single-use nonce for a purpose (and optionally a subject it is bound to).
 */
final readonly class IssueNonceRequest
{
    public function __construct(
        public string $purpose,
        public ?int $ttl = null,
        public ?Model $subject = null,
    ) {}
}
