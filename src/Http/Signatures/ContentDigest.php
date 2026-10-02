<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use RoundlyConsulting\Crypto\Hash\ConstantTime;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\StructuredFieldException;
use RoundlyConsulting\Sentinel\Http\StructuredFields\ByteSequence;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Item;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parser;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Serializer;

/**
 * RFC 9530 `Content-Digest`: `sha-256=:…:` or `sha-512=:…:` over the raw body. On receipt,
 * every supported member must match (in constant time); deprecated or unknown algorithms are
 * ignored, and a header with none we support is refused.
 *
 * @internal
 */
final class ContentDigest
{
    public static function header(string $body, DigestAlgorithm $algorithm): string
    {
        return Serializer::dictionary([$algorithm->value => new Item(new ByteSequence((new Digest($algorithm->hashAlgorithm()))->raw($body)))]);
    }

    /**
     * Null when the digest matches; otherwise why not.
     *
     * @param  list<string>  $lines
     */
    public static function verify(array $lines, string $body): ?SignatureRejection
    {
        try {
            $members = Parser::dictionary($lines);
        } catch (StructuredFieldException) {
            return SignatureRejection::Malformed;
        }

        $checked = 0;

        foreach ($members as $name => $member) {
            $algorithm = DigestAlgorithm::tryFrom((string) $name);

            if ($algorithm === null) {
                continue;
            }

            if (! $member instanceof Item || ! $member->value instanceof ByteSequence) {
                return SignatureRejection::Malformed;
            }

            if (! ConstantTime::equals((new Digest($algorithm->hashAlgorithm()))->raw($body), $member->value->bytes)) {
                return SignatureRejection::DigestMismatch;
            }

            $checked++;
        }

        return $checked === 0 ? SignatureRejection::UnsupportedDigest : null;
    }
}
