<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Http\Messages\MessageView;
use RoundlyConsulting\Sentinel\Http\StructuredFields\InnerList;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Serializer;

/**
 * The RFC 9421 §2.5 signature base: one `"<component>": <value>` line per covered component,
 * in order, then `"@signature-params": <the serialized inner list>`; lines joined by `\n`, no
 * trailing newline.
 *
 * @internal
 */
final class SignatureBase
{
    public static function build(MessageView $message, InnerList $parameters): string
    {
        $lines = [];

        foreach (self::components($parameters) as $component) {
            $lines[] = '"'.$component.'": '.ComponentResolver::value($message, $component);
        }

        $lines[] = '"@signature-params": '.Serializer::innerList($parameters);

        return implode("\n", $lines);
    }

    /**
     * The covered component names: strings, lowercase, without parameters, each once.
     *
     * @return list<string>
     */
    public static function components(InnerList $parameters): array
    {
        $components = [];

        foreach ($parameters->items as $item) {
            if (! is_string($item->value) || $item->value === '' || strtolower($item->value) !== $item->value) {
                throw HttpSignatureException::rejected(SignatureRejection::Malformed);
            }

            if (! $item->parameters->isEmpty() || ! ComponentResolver::supported($item->value)) {
                throw HttpSignatureException::rejected(SignatureRejection::UnsupportedComponent);
            }

            if (in_array($item->value, $components, true)) {
                throw HttpSignatureException::rejected(SignatureRejection::Malformed);
            }

            $components[] = $item->value;
        }

        return $components;
    }
}
