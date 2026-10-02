<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

use Illuminate\Http\Request;

/**
 * Whose idempotency key this is. The default (`Idempotency\RequestScope`) uses the
 * authenticated user, else a verified HTTP-signature key, else the client IP — so two
 * clients can never collide on, or replay, each other's keys. Rebind to change it.
 */
interface IdempotencyScopeResolver
{
    public function resolve(Request $request): string;
}
