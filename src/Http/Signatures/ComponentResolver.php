<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Http\Messages\MessageView;

/**
 * Component values (RFC 9421 §2): the derived components of this profile and header fields
 * (every field line, OWS trimmed, obs-fold replaced, joined by `, `). Component parameters,
 * `@request-target` and `@query-param` are unsupported; a component the message cannot
 * provide is missing.
 *
 * @internal
 */
final class ComponentResolver
{
    public const array REQUEST_DERIVED = ['@method', '@target-uri', '@authority', '@scheme', '@path', '@query'];

    public static function value(MessageView $message, string $component): string
    {
        if (str_starts_with($component, '@')) {
            return self::derived($message, $component);
        }

        if (preg_match('/^[a-z0-9!#$%&\'*+.^_`|~-]+$/D', $component) !== 1) {
            throw HttpSignatureException::rejected(SignatureRejection::Malformed);
        }

        $lines = $message->header($component) ?? throw HttpSignatureException::rejected(SignatureRejection::MissingComponent);

        return implode(', ', array_map(
            static fn (string $line): string => trim((string) preg_replace('/\r?\n[ \t]+/', ' ', $line), " \t"),
            $lines,
        ));
    }

    public static function supported(string $component): bool
    {
        return ! str_starts_with($component, '@') || in_array($component, [...self::REQUEST_DERIVED, '@status'], true);
    }

    private static function derived(MessageView $message, string $component): string
    {
        if (! self::supported($component)) {
            throw HttpSignatureException::rejected(SignatureRejection::UnsupportedComponent);
        }

        $value = match ($component) {
            '@method' => $message->method(),
            '@authority' => $message->authority(),
            '@scheme' => $message->scheme(),
            '@path' => $message->path(),
            '@query' => $message->query() === null ? null : '?'.$message->query(),
            '@target-uri' => $message->isRequest()
                ? $message->scheme().'://'.$message->authority().$message->path().($message->query() === '' ? '' : '?'.$message->query())
                : null,
            default => $message->status() === null ? null : (string) $message->status(),
        };

        return $value ?? throw HttpSignatureException::rejected(SignatureRejection::UnsupportedComponent);
    }
}
