<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Signatures;

use Psr\Http\Message\RequestInterface;
use RoundlyConsulting\Crypto\Random\Csprng;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
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
        $ring = $options->ring ?? Settings::outboundRing();
        $key = $this->keys->find($ring, $keyId) ?? throw UnknownKeyException::inRing($ring, $keyId);

        if (! $key->canSign()) {
            throw NoSigningKeyException::forRing($ring);
        }

        if (! $key->algorithm()->isHttpRegistered()) {
            throw AlgorithmNotAllowedException::forRing($ring, $key->algorithm());
        }

        $view = new PsrRequestView($request);
        $body = $view->body();
        $components = [];

        foreach ($options->components ?? Settings::outboundComponents() as $component) {
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
        $expiresIn = $options->expiresIn ?? Settings::outboundExpiresIn();
        $tag = $options->tag ?? Settings::outboundTag();
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
        $label = $options->label ?? Settings::outboundLabel();

        $inputs = $request->hasHeader('Signature-Input') ? Parser::dictionary(array_values($request->getHeader('Signature-Input'))) : [];
        $signatures = $request->hasHeader('Signature') ? Parser::dictionary(array_values($request->getHeader('Signature'))) : [];
        $inputs[$label] = $input;
        $signatures[$label] = new Item(new ByteSequence($signature));

        return $request
            ->withHeader('Signature-Input', Serializer::dictionary($inputs))
            ->withHeader('Signature', Serializer::dictionary($signatures));
    }
}
