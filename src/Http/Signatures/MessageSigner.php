<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use GuzzleHttp\Psr7\HttpFactory;
use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\InvalidSentinelConfigurationException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Http\Messages\PsrRequestView;
use RoundlyConsulting\Sentinel\Http\StructuredFields\ByteSequence;
use RoundlyConsulting\Sentinel\Http\StructuredFields\InnerList;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Item;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parameters;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parser;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Serializer;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\Purpose;
use RoundlyConsulting\Sentinel\Keys\Signers;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Signs the final outgoing PSR-7 request (plan §4.11.6): adds `Content-Digest` when the body
 * is covered, leaves out `@query` without a query and headers the request does not carry,
 * and merges its member into any existing `Signature-Input` / `Signature` dictionaries.
 * Parameters: `created`, optional `expires`, `keyid`, a fresh `nonce`, optional `alg`, `tag`.
 *
 * @internal
 */
final readonly class MessageSigner
{
    public function __construct(
        private KeyStoreManager $keys,
        private Signers $signers,
        private Csprng $random = new Csprng,
    ) {}

    public function sign(RequestInterface $request, string $keyId, SigningOptions $options): RequestInterface
    {
        $ring = self::ring($options);
        $requested = self::components($options);
        $expiresIn = self::expiresIn($options);
        $tag = self::tag($options);
        $label = self::label($options);
        $key = $this->keys->find($ring, $keyId) ?? throw UnknownKeyException::inRing($ring, $keyId);

        if (! $key->canSign()) {
            throw NoSigningKeyException::forRing($ring);
        }

        // An algorithm RFC 9421 does not register, or one the ring's allow-list retired.
        if (! $key->algorithm()->isHttpRegistered() || ! Settings::ring($ring)->allows($key->algorithm())) {
            throw AlgorithmNotAllowedException::forRing($ring, $key->algorithm());
        }

        $view = new PsrRequestView($request);
        // The body is read only for a digest — and a stream that cannot rewind is buffered
        // first, so the request never goes out with the body signing consumed.
        [$request, $body] = in_array('content-digest', $requested, true) ? self::buffered($request) : [$request, ''];
        $components = [];

        foreach ($requested as $component) {
            if ($component === 'content-digest' && $body !== '') {
                $request = $request->withHeader('Content-Digest', ContentDigest::header($body, $options->digest ?? Settings::outboundDigest()));
            }

            $absent = match (true) {
                $component === '@query' => $view->query() === '',
                $component === 'content-digest' => $body === '',
                str_starts_with($component, '@') => false,
                default => ! $request->hasHeader($component),
            };

            if (! $absent) {
                $components[] = new Item($component);
            }
        }

        $created = Clock::now()->getTimestamp();
        $values = ['created' => $created];

        if ($expiresIn !== null) {
            $values['expires'] = $created + $expiresIn;
        }

        $values['keyid'] = $keyId;

        if ($options->nonce) {
            $values['nonce'] = $this->random->token(32);
        }

        if ($options->includeAlg ?? Settings::outboundIncludesAlg()) {
            $values['alg'] = $key->algorithm()->value;
        }

        if ($tag !== null) {
            $values['tag'] = $tag;
        }

        $input = new InnerList($components, new Parameters($values));
        $signature = $this->signers->sign($key, Purpose::Http, SignatureBase::build(new PsrRequestView($request), $input));

        $inputs = $request->hasHeader('Signature-Input') ? Parser::dictionary(array_values($request->getHeader('Signature-Input'))) : [];
        $signatures = $request->hasHeader('Signature') ? Parser::dictionary(array_values($request->getHeader('Signature'))) : [];
        $inputs[$label] = $input;
        $signatures[$label] = new Item(new ByteSequence($signature));

        return $request
            ->withHeader('Signature-Input', Serializer::dictionary($inputs))
            ->withHeader('Signature', Serializer::dictionary($signatures));
    }

    /*
     * Each option is checked like its `signatures.outbound.*` counterpart — a null falls back
     * to the configuration — so a mistake fails here, never as a dead or empty signature.
     */

    private static function ring(SigningOptions $options): string
    {
        if ($options->ring === null) {
            return Settings::outboundRing();
        }

        return in_array($options->ring, Settings::rings(), true) ? $options->ring : throw InvalidSentinelConfigurationException::invalidSigningOption('ring', 'must name a configured key ring');
    }

    /**
     * @return list<string>
     */
    private static function components(SigningOptions $options): array
    {
        if ($options->components === null) {
            return Settings::outboundComponents();
        }

        try {
            $components = ProfileResolver::components('signatures.outbound.components', $options->components);
        } catch (InvalidSentinelConfigurationException) {
            $components = [];
        }

        return $components !== [] ? $components : throw InvalidSentinelConfigurationException::invalidSigningOption('components', 'must be a non-empty list of lowercase, supported component names');
    }

    private static function expiresIn(SigningOptions $options): ?int
    {
        if ($options->expiresIn === null) {
            return Settings::outboundExpiresIn();
        }

        return $options->expiresIn >= 1 && $options->expiresIn <= 86400 ? $options->expiresIn : throw InvalidSentinelConfigurationException::invalidSigningOption('expiresIn', 'must be between 1 and 86400 seconds');
    }

    private static function tag(SigningOptions $options): ?string
    {
        if ($options->tag === null) {
            return Settings::outboundTag();
        }

        return ProfileResolver::isTag($options->tag) ? $options->tag : throw InvalidSentinelConfigurationException::invalidSigningOption('tag', 'must be 1–255 printable ASCII characters');
    }

    private static function label(SigningOptions $options): string
    {
        if ($options->label === null) {
            return Settings::outboundLabel();
        }

        return ProfileResolver::isLabel($options->label) ? $options->label : throw InvalidSentinelConfigurationException::invalidSigningOption('label', 'must be a signature label ([a-z*][a-z0-9_-.*], at most 64 characters)');
    }

    /**
     * The request and its body bytes; a non-seekable body is replaced by a buffered copy.
     *
     * The copy is built with Guzzle's PSR-7 `HttpFactory`. That is no runtime require of this
     * package: `guzzlehttp/psr7` comes with `illuminate/http` (the HTTP client Laravel ships),
     * which is required, so the class is always present (pinned in ArchTest).
     *
     * @return array{RequestInterface, string}
     */
    private static function buffered(RequestInterface $request): array
    {
        $stream = $request->getBody();

        if ($stream->isSeekable()) {
            return [$request, (new PsrRequestView($request))->body()];
        }

        $content = $stream->getContents();

        return [$request->withBody((new HttpFactory)->createStream($content)), $content];
    }
}
