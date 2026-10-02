<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Illuminate\Http\Request;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\Canonical\BinarySafe;
use RoundlyConsulting\Sentinel\Canonical\Jcs;

/**
 * The digests idempotency is keyed by (plan §4.9.3–4):
 *
 *  - the key digest binds the scope, the route and the client's key — the key itself is never
 *    stored;
 *  - the fingerprint binds the method, the raw path and query, the content type and the raw
 *    body: semantically equal JSON with other whitespace is another payload (D28).
 *
 * Raw request bytes that are not UTF-8 enter through {@see BinarySafe}, so no two different
 * requests share a fingerprint.
 *
 * @internal
 */
final class RequestFingerprint
{
    public static function key(string $scope, string $route, string $key): string
    {
        return self::digest(['sentinel.idem/1', BinarySafe::value($scope), BinarySafe::value($route), BinarySafe::value($key)]);
    }

    public static function request(Request $request): string
    {
        $target = (string) $request->server->get('REQUEST_URI', '/');
        $path = explode('?', $target, 2)[0];
        $query = $request->server->get('QUERY_STRING');

        return self::digest([
            'sentinel.idem-fp/1',
            BinarySafe::value(strtoupper((string) $request->server->get('REQUEST_METHOD', $request->getMethod()))),
            BinarySafe::value($path === '' ? '/' : $path),
            BinarySafe::value(is_string($query) ? $query : ''),
            BinarySafe::value((string) $request->headers->get('content-type', '')),
            Base64Url::encode((new Digest)->raw($request->getContent())),
        ]);
    }

    /**
     * A programmatic call's fingerprint (its arguments, as the caller describes them).
     */
    public static function call(?string $fingerprint): string
    {
        return self::digest(['sentinel.idem-fp/1', 'call', BinarySafe::value($fingerprint ?? '')]);
    }

    /**
     * @param  list<string|list<string>|null>  $parts
     */
    private static function digest(array $parts): string
    {
        return Base64Url::encode((new Digest)->raw(Jcs::encode($parts)));
    }
}
