<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Middleware;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use RoundlyConsulting\Sentinel\Exceptions\HttpSignatureException;
use RoundlyConsulting\Sentinel\Exceptions\SealingMisconfiguredException;
use RoundlyConsulting\Sentinel\Http\Signatures\ProfileResolver;
use RoundlyConsulting\Sentinel\Http\StructuredFields\InnerList;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Item;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Parameters;
use RoundlyConsulting\Sentinel\Http\StructuredFields\Serializer;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Settings;
use Symfony\Component\HttpFoundation\Response;

/**
 * `sentinel.signed[:profile]` — require a valid RFC 9421 HTTP message signature. The
 * verified signature is available as `Sentinel::signatures()->current($request)` (the
 * `sentinel.signature` request attribute), its key's owner as
 * `Sentinel::signatures()->owner($request)`. A rejection answers 401 problem details (a
 * generic code unless `app.debug`) with an `Accept-Signature` advertisement of what this
 * request needed. Place it before `auth` when signatures authenticate API clients.
 */
final readonly class VerifyHttpSignature
{
    /** The request attribute holding the VerifiedSignature. */
    public const string ATTRIBUTE = 'sentinel.signature';

    public function __construct(private Container $container) {}

    /**
     * The middleware for a configured profile, validated when the route is declared:
     * `->middleware(VerifyHttpSignature::profile('partners'))`. Null = the default profile.
     *
     * @throws SealingMisconfiguredException for a profile not in `sentinel.signatures.profiles`
     */
    public static function profile(?string $profile = null): string
    {
        if ($profile === null) {
            return self::class;
        }

        $profiles = config('sentinel.signatures.profiles');

        if (! is_array($profiles) || ! array_key_exists($profile, $profiles) || preg_match('/^[a-z][a-z0-9_-]{0,63}$/D', $profile) !== 1) {
            throw SealingMisconfiguredException::middlewareOption('sentinel.signed', $profile);
        }

        return self::class.':'.$profile;
    }

    public function handle(Request $request, Closure $next, ?string $profile = null): Response
    {
        try {
            $signature = $this->container->make(SentinelManager::class)->verifyRequestSignature($request, $profile);
        } catch (HttpSignatureException $exception) {
            throw $exception->advertising(Settings::advertisesSignatures() ? self::advertisement($request, $profile) : null);
        }

        $request->attributes->set(self::ATTRIBUTE, $signature);

        $response = $next($request);

        return $response instanceof Response ? $response : new Response(is_scalar($response) ? (string) $response : '');
    }

    /**
     * RFC 9421 §5.1 `Accept-Signature`: the components this request had to cover, and the
     * parameters it had to carry.
     */
    private static function advertisement(Request $request, ?string $name): string
    {
        $profile = ProfileResolver::resolve($name);
        $components = $profile->components;
        $query = $request->server->get('QUERY_STRING');

        if ($profile->requireQuery && is_string($query) && $query !== '') {
            $components[] = '@query';
        }

        if ($profile->requireContentDigest && $request->getContent() !== '') {
            $components[] = 'content-digest';
        }

        $parameters = ['created' => true];

        if ($profile->requireNonce) {
            $parameters['nonce'] = true;
        }

        if ($profile->tag !== null) {
            $parameters['tag'] = $profile->tag;
        }

        return Serializer::dictionary([
            $profile->label ?? 'sig1' => new InnerList(array_map(static fn (string $component): Item => new Item($component), array_values(array_unique($components))), new Parameters($parameters)),
        ]);
    }
}
