<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Canonical;

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use RoundlyConsulting\Crypto\Hash\Hmac;
use RoundlyConsulting\Sentinel\Keys\Hkdf;
use RoundlyConsulting\Sentinel\Keys\SealingKey;

/**
 * Keyed per-field tags (`sentinel.field/1`, plan §4.3.5) that tell an operator *which*
 * attributes changed without storing or leaking values: 128-bit truncated HMAC-SHA-256
 * under a field subkey (HKDF purpose `field`). Diagnostics only — the seal MAC decides
 * integrity, and tampering with tags merely misleads the diff.
 *
 * Produced for HMAC keys only (an asymmetric seal stores no tags → changed attributes are
 * "unknown").
 *
 * @internal
 */
final readonly class FieldTagger
{
    public const string VERSION = 'sentinel.field/1';

    public const int TAG_BYTES = 16;

    /**
     * @return array<string, string>|null tag per field name, or null for a non-HMAC key
     */
    public function tags(SealingKey $key, SealMessage $message): ?array
    {
        if (! $key->algorithm()->isHmac()) {
            return null;
        }

        $fieldKey = Hkdf::derive(HashAlgorithm::Sha256, $key->material()->hmacRoot(), 32, Hkdf::fieldInfo($key->ring, $key->keyId));
        $hmac = new Hmac(HashAlgorithm::Sha256);
        $tags = [];

        foreach ($message->fields as $field) {
            $document = Jcs::encode([
                self::VERSION, $message->context, $message->type, $message->table, $message->id, $message->scope,
                $message->seal, (string) $message->version, $field->name, $field->tag, $field->value,
            ]);

            $tags[$field->name] = Base64Url::encode(substr($hmac->sign($document, $fieldKey), 0, self::TAG_BYTES));
        }

        ksort($tags, SORT_STRING);

        return $tags;
    }

    /**
     * The names whose tags differ (constant-time), plus names present on one side only —
     * sorted bytewise.
     *
     * @param  array<array-key, mixed>  $stored  decoded `field_tags` column (untrusted)
     * @param  array<string, string>  $current
     * @return list<string>
     */
    public function changed(array $stored, array $current): array
    {
        $changed = [];

        foreach ($current as $name => $tag) {
            $theirs = $stored[$name] ?? null;

            if (! is_string($theirs) || ! ConstantTime::equals($tag, $theirs)) {
                $changed[] = $name;
            }
        }

        foreach (array_keys($stored) as $name) {
            if (! array_key_exists((string) $name, $current)) {
                $changed[] = (string) $name;
            }
        }

        $changed = array_values(array_unique($changed));
        sort($changed, SORT_STRING);

        return $changed;
    }
}
