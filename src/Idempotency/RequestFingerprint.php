<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Idempotency;

use Illuminate\Http\Request;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Hash\Digest;
use RoundlyConsulting\Sentinel\Canonical\BinarySafe;
use RoundlyConsulting\Sentinel\Canonical\Jcs;
use Symfony\Component\HttpFoundation\File\UploadedFile;

/**
 * The digests idempotency is keyed by (plan §4.9.3–4):
 *
 *  - the key digest binds the scope, the route and the client's key — the key itself is never
 *    stored;
 *  - the fingerprint binds the method, the raw path and query, the content type and the raw
 *    body: semantically equal JSON with other whitespace is another payload (D28). A
 *    `multipart/form-data` body never reaches PHP raw (`php://input` is empty while
 *    `enable_post_data_reading` is on): its fields (in order) and its files (name, size and
 *    SHA-256 of the contents) are bound instead.
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

        $content = $request->getContent();
        $parts = [
            'sentinel.idem-fp/1',
            BinarySafe::value(strtoupper((string) $request->server->get('REQUEST_METHOD', $request->getMethod()))),
            BinarySafe::value($path === '' ? '/' : $path),
            BinarySafe::value(is_string($query) ? $query : ''),
            BinarySafe::value((string) $request->headers->get('content-type', '')),
            Base64Url::encode((new Digest)->raw($content)),
        ];

        // No raw body but parsed fields or files: the multipart payload is only here.
        if ($content === '' && ($request->request->all() !== [] || $request->files->all() !== [])) {
            $parts[] = Base64Url::encode((new Digest)->raw(Jcs::encode([self::fields($request->request->all()), self::files($request->files->all())])));
        }

        return self::digest($parts);
    }

    /**
     * Form fields in the order received, keys and values binary-safe.
     *
     * @param  array<array-key, mixed>  $fields
     * @return list<list<mixed>>
     */
    private static function fields(array $fields): array
    {
        $pairs = [];

        foreach ($fields as $name => $value) {
            $pairs[] = [BinarySafe::value((string) $name), is_array($value) ? self::fields($value) : BinarySafe::value(is_scalar($value) ? (string) $value : null)];
        }

        return $pairs;
    }

    /**
     * Uploaded files by their client name, size and SHA-256 of the contents.
     *
     * @param  array<array-key, mixed>  $files
     * @return list<list<mixed>>
     */
    private static function files(array $files): array
    {
        $pairs = [];

        foreach ($files as $name => $file) {
            $pairs[] = [BinarySafe::value((string) $name), match (true) {
                is_array($file) => self::files($file),
                $file instanceof UploadedFile => [
                    BinarySafe::value($file->getClientOriginalName()), (string) $file->getSize(),
                    Base64Url::encode((new Digest)->raw($file->isFile() ? $file->getContent() : '')),
                ],
                default => null,
            }];
        }

        return $pairs;
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
