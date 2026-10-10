<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\MacRejection;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Support\Settings;
use SensitiveParameter;

/**
 * The rules `mac()` and `verifyMac()` share with `Sentinel::fake()`, so the fake refuses what
 * production refuses: which rings may hold MAC keys, which keys verify, and the one MAC
 * encoding (unpadded base64url, strictly parsed).
 *
 * @internal
 */
final class MacRules
{
    /**
     * The ring, unless seals, the ledger or HTTP message signatures use it. MAC secrets are
     * shared with peers: in a seal or ledger ring a peer could derive the HKDF subkeys, and in
     * a signature ring a MAC over a signature base would be a valid HTTP signature.
     *
     * @throws SealingMisconfiguredException
     */
    public static function ring(string $ring): RingConfig
    {
        $config = Settings::ring($ring);

        if (in_array($ring, [...Settings::ledgerRings(), ...Settings::signatureRings()], true)) {
            throw SealingMisconfiguredException::notAMacRing($ring);
        }

        return $config;
    }

    /**
     * Why a key verifies no MAC, or null when it does: active and verify-only keys do; an
     * `hmac-*` algorithm the ring allows is required.
     */
    public static function refusal(RingConfig $ring, KeyStatus $status, Algorithm $algorithm): ?MacRejection
    {
        return match (true) {
            $status === KeyStatus::Revoked => MacRejection::RevokedKey,
            $status === KeyStatus::Retired => MacRejection::RetiredKey,
            $status === KeyStatus::Pending => MacRejection::PendingKey,
            ! $algorithm->isHmac() => MacRejection::UnsupportedAlgorithm,
            ! $ring->allows($algorithm) => MacRejection::AlgorithmNotAllowed,
            default => null,
        };
    }

    /**
     * The MAC's bytes, or null when it is not canonical unpadded base64url — padding, `+` or
     * `/`, whitespace, any other byte, a non-canonical final character and the empty string
     * all are refused. The length is the caller's to check, after the compare.
     */
    public static function decode(#[SensitiveParameter] string $mac): ?string
    {
        try {
            return Base64Url::decode($mac);
        } catch (InvalidEncodingException) {
            return null;
        }
    }

    /**
     * The wire form of raw MAC bytes.
     */
    public static function encode(#[SensitiveParameter] string $mac): string
    {
        return Base64Url::encode($mac);
    }
}
