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
     * @param  string|null  $messages  the translation entry of title and detail (default: the code's)
     */
    public static function response(int $status, string $code, array $headers = [], ?string $messages = null): JsonResponse
    {
        $base = Settings::problemTypeBase();
        $messages ??= $code;
        $title = self::message("sentinel::messages.problems.{$messages}.title");
        $detail = self::message("sentinel::messages.problems.{$messages}.detail");

        $body = array_filter([
            'type' => $base === null ? null : $base.'#'.$code,
            'title' => $title ?? $code,
            'status' => $status,
            'detail' => $detail,
            'code' => $code,
        ], static fn (mixed $value): bool => $value !== null);

        return new JsonResponse($body, $status, [...$headers, 'Content-Type' => 'application/problem+json'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function message(string $key): ?string
    {
        $message = trans($key);

        return is_string($message) && $message !== $key ? $message : null;
    }
}
