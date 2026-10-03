<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use Closure;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Exceptions\StructuredFieldException;
use RoundlyConsulting\Sentinel\Http\Messages\MessageView;
use RoundlyConsulting\Sentinel\Http\StructuredFields\ByteSequence;
use RoundlyConsulting\Sentinel\Http\StructuredFields\InnerList;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Item;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parameters;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parser;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * Verifies an RFC 9421 signature against a profile (plan §4.11.5), in exactly this order:
 * select the label → required parameters → covered components → time window → key (from
 * the profile's ring only; the algorithm from the key) → Content-Digest → the signature →
 * and only then the nonce, so unauthenticated requests can never fill the nonce store.
 * Everything unsupported fails closed.
 *
 * @internal
 */
final readonly class SignatureVerifier
{
    private const int MAX_NONCE_LENGTH = 256;

    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
    ) {}

    /**
     * @param  Closure(string $purpose, string $nonce, int $until): bool  $remember  false = replay
     *
     * @throws HttpSignatureException
     */
    public function verify(MessageView $message, SignatureProfile $profile, Closure $remember): VerifiedSignature
    {
        $selected = $this->select($message, $profile);
        $input = $selected->input;
        $components = SignatureBase::components($input);
        $parameters = $input->parameters;

        $keyId = self::string($parameters, 'keyid', true) ?? throw HttpSignatureException::rejected(SignatureRejection::MissingParameter);
        $created = self::integer($parameters, 'created', true) ?? throw HttpSignatureException::rejected(SignatureRejection::MissingParameter, $keyId);
        $expires = self::integer($parameters, 'expires', false);
        $nonce = self::string($parameters, 'nonce', $profile->requireNonce && $message->isRequest());
        $tag = self::string($parameters, 'tag', false);
        $alg = self::string($parameters, 'alg', false);

        if ($profile->tag !== null && $tag !== $profile->tag) {
            throw HttpSignatureException::rejected(SignatureRejection::TagMismatch, $keyId);
        }

        if ($nonce !== null && strlen($nonce) > self::MAX_NONCE_LENGTH) {
            throw HttpSignatureException::rejected(SignatureRejection::Malformed, $keyId);
        }

        $this->coverage($message, $profile, $components, $keyId);
        $this->window($profile, $created, $expires, $keyId);
        $key = $this->key($profile, $keyId, $alg);

        if (in_array('content-digest', $components, true) || $message->header('content-digest') !== null) {
            // Without the raw bytes no digest can be checked: never take one on trust.
            $rejection = $message->bodyUnavailable()
                ? SignatureRejection::DigestMismatch
                : ContentDigest::verify($message->header('content-digest') ?? [], $message->body());

            if ($rejection !== null) {
                throw HttpSignatureException::rejected($rejection, $keyId);
            }
        }

        if (! $this->signers->verify($key, Purpose::Http, SignatureBase::build($message, $input), $selected->signature)) {
            throw HttpSignatureException::rejected(SignatureRejection::InvalidSignature, $keyId);
        }

        if ($nonce !== null && ! $remember(self::noncePurpose($key), $nonce, $created + $profile->maxAge + $profile->clockSkew)) {
            throw HttpSignatureException::rejected(SignatureRejection::Replayed, $keyId);
        }

        return new VerifiedSignature($selected->label, $key->ring, $keyId, $key->algorithm(), $created, $expires, $nonce, $tag, $components, $key->ownerType, $key->ownerId);
    }

    /**
     * The nonce scope of one key (internal purposes may exceed the public purpose grammar).
     */
    public static function noncePurpose(SealingKey $key): string
    {
        return 'http:'.substr((new Digest)->hex($key->ring."\0".$key->keyId), 0, 40);
    }

    private function select(MessageView $message, SignatureProfile $profile): SelectedSignature
    {
        $inputs = $message->header('signature-input');
        $signatures = $message->header('signature');

        if ($inputs === null || $signatures === null) {
            throw HttpSignatureException::rejected(SignatureRejection::Missing);
        }

        try {
            $inputs = Parser::dictionary($inputs);
            $signatures = Parser::dictionary($signatures);
        } catch (StructuredFieldException) {
            throw HttpSignatureException::rejected(SignatureRejection::Malformed);
        }

        $label = match (true) {
            $profile->label !== null => $profile->label,
            count($inputs) === 1 => (string) array_key_first($inputs),
            $profile->tag !== null => self::taggedLabel($inputs, $profile->tag),
            default => throw HttpSignatureException::rejected(SignatureRejection::Ambiguous),
        };

        if (! isset($inputs[$label], $signatures[$label])) {
            throw HttpSignatureException::rejected(SignatureRejection::Missing);
        }

        $input = $inputs[$label];
        $signature = $signatures[$label];

        if (! $input instanceof InnerList || ! $signature instanceof Item || ! $signature->value instanceof ByteSequence) {
            throw HttpSignatureException::rejected(SignatureRejection::Malformed);
        }

        return new SelectedSignature($label, $input, $signature->value->bytes);
    }

    /**
     * @param  array<string, Item|InnerList>  $inputs
     */
    private static function taggedLabel(array $inputs, string $tag): string
    {
        foreach ($inputs as $label => $input) {
            if ($input instanceof InnerList && $input->parameters->get('tag') === $tag) {
                return (string) $label;
            }
        }

        throw HttpSignatureException::rejected(SignatureRejection::Ambiguous);
    }

    /**
     * @param  list<string>  $components
     */
    private function coverage(MessageView $message, SignatureProfile $profile, array $components, string $keyId): void
    {
        // The signed `@method` must be the method that runs: a method override (an uncovered
        // header or form field) would execute a signed POST as a DELETE.
        if ($message->methodOverridden()) {
            throw HttpSignatureException::rejected(SignatureRejection::Malformed, $keyId);
        }

        $required = $message->isRequest()
            ? $profile->components
            : [...array_values(array_diff($profile->components, ComponentResolver::REQUEST_DERIVED)), '@status'];

        if ($message->isRequest() && $profile->requireQuery && $message->query() !== '') {
            $required[] = '@query';
        }

        // A multipart body PHP parsed away is a body all the same: it must be covered.
        if ($profile->requireContentDigest && ($message->body() !== '' || $message->bodyUnavailable())) {
            $required[] = 'content-digest';
        }

        if (array_diff($required, $components) !== []) {
            throw HttpSignatureException::rejected(SignatureRejection::MissingComponent, $keyId);
        }
    }

    /**
     * Inclusive boundaries, widened by the clock skew.
     */
    private function window(SignatureProfile $profile, int $created, ?int $expires, string $keyId): void
    {
        $now = Clock::now()->getTimestamp();

        $rejection = match (true) {
            $created > $now + $profile->clockSkew => SignatureRejection::NotYetValid,
            $created < $now - $profile->maxAge - $profile->clockSkew => SignatureRejection::TooOld,
            $expires !== null && $expires < $now - $profile->clockSkew => SignatureRejection::Expired,
            default => null,
        };

        if ($rejection !== null) {
            throw HttpSignatureException::rejected($rejection, $keyId);
        }
    }

    /**
     * The key named by `keyid` in the profile's ring — its algorithm is the only one used.
     */
    private function key(SignatureProfile $profile, string $keyId, ?string $alg): SealingKey
    {
        try {
            $lookup = $this->keys->lookup($profile->ring, $keyId);
        } catch (SealingMisconfiguredException) {
            throw HttpSignatureException::rejected(SignatureRejection::UnknownKey, $keyId);
        }

        $key = $lookup->key ?? throw HttpSignatureException::rejected(SignatureRejection::UnknownKey, $keyId);

        $rejection = match (true) {
            $key->status === KeyStatus::Pending, $key->status === KeyStatus::Retired => SignatureRejection::UnknownKey,
            $key->status === KeyStatus::Revoked => SignatureRejection::RevokedKey,
            $alg !== null && Algorithm::tryFrom($alg)?->isHttpRegistered() !== true, ! $key->algorithm()->isHttpRegistered() => SignatureRejection::UnsupportedAlgorithm,
            $alg !== null && $alg !== $key->algorithm()->value => SignatureRejection::AlgorithmMismatch,
            ! $profile->allows($key->algorithm()) => SignatureRejection::AlgorithmNotAllowed,
            default => null,
        };

        if ($rejection !== null) {
            throw HttpSignatureException::rejected($rejection, $keyId);
        }

        return $key;
    }

    private static function string(Parameters $parameters, string $name, bool $required): ?string
    {
        $value = $parameters->get($name);

        return match (true) {
            is_string($value) => $value,
            $value === null && $required => throw HttpSignatureException::rejected(SignatureRejection::MissingParameter),
            $value === null => null,
            default => throw HttpSignatureException::rejected(SignatureRejection::Malformed),
        };
    }

    private static function integer(Parameters $parameters, string $name, bool $required): ?int
    {
        $value = $parameters->get($name);

        return match (true) {
            is_int($value) => $value,
            $value === null && $required => throw HttpSignatureException::rejected(SignatureRejection::MissingParameter),
            $value === null => null,
            default => throw HttpSignatureException::rejected(SignatureRejection::Malformed),
        };
    }
}
