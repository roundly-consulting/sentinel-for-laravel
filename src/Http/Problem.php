<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http;

use Illuminate\Http\JsonResponse;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * RFC 9457 problem details (`application/problem+json`) for Sentinel's HTTP rejections, with a
 * machine-readable `code`. `type` is `<problems.type_base>#<code>` when a base is configured,
 * else omitted (`about:blank`). Title and detail are translated (`sentinel::messages`).
 *
 * @internal
 */
final class Problem
{
    /**
     * @param  array<string, string>  $headers
     */
    public static function response(int $status, string $code, array $headers = []): JsonResponse
    {
        $base = Settings::problemTypeBase();
        $title = trans("sentinel::messages.problems.{$code}.title");
        $detail = trans("sentinel::messages.problems.{$code}.detail");

        $body = array_filter([
            'type' => $base === null ? null : $base.'#'.$code,
            'title' => is_string($title) ? $title : $code,
            'status' => $status,
            'detail' => is_string($detail) ? $detail : null,
            'code' => $code,
        ], static fn (mixed $value): bool => $value !== null);

        return new JsonResponse($body, $status, [...$headers, 'Content-Type' => 'application/problem+json'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
