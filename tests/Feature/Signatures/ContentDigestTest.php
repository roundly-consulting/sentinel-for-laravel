<?php

declare(strict_types=1);

use RoundlyConsulting\Sentinel\Enums\DigestAlgorithm;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Facades\Sentinel;
use RoundlyConsulting\Sentinel\Http\Signatures\ContentDigest;

/**
 * §10 item 50: RFC 9530 Content-Digest.
 */
it('computes the RFC 9530 and RFC 9421 sample digests', function (string $body, DigestAlgorithm $algorithm, string $expected): void {
    expect(Sentinel::signatures()->contentDigest($body, $algorithm))->toBe($expected)
        ->and(ContentDigest::verify([$expected], $body))->toBeNull();
})->with([
    'RFC 9530 sha-256' => ['{"hello": "world"}', DigestAlgorithm::Sha256, 'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:'],
    'empty body' => ['', DigestAlgorithm::Sha256, 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:'],
    'RFC 9421 test-request sha-512' => ['{"hello": "world"}', DigestAlgorithm::Sha512, 'sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:'],
]);

it('checks every supported member and ignores deprecated ones', function (array $lines, ?SignatureRejection $expected): void {
    expect(ContentDigest::verify($lines, '{"hello": "world"}'))->toBe($expected);
})->with([
    'both supported, both right' => [['sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:'], null],
    'a deprecated member beside a right one' => [['md5=:Sd/dVLAcvNLSq16eXua5uQ==:, sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:'], null],
    'one of two members wrong' => [['sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, sha-512=:AAAA:'], SignatureRejection::DigestMismatch],
    'a wrong digest' => [['sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:'], SignatureRejection::DigestMismatch],
    'only a deprecated algorithm' => [['md5=:Sd/dVLAcvNLSq16eXua5uQ==:'], SignatureRejection::UnsupportedDigest],
    'not a dictionary' => [['sha-256=:X48E9q'], SignatureRejection::Malformed],
    'a token, not bytes' => [['sha-256=X48E9q'], SignatureRejection::Malformed],
    'not bytes' => [['sha-256="X48E9q"'], SignatureRejection::Malformed],
]);
