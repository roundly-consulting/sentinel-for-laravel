<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Closure;
use RoundlyConsulting\Crypto\Cose\UnsupportedAlgorithmException;
use RoundlyConsulting\Crypto\Exceptions\CryptoException;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;

/**
 * The one place where crypto-for-laravel failures become Sentinel's. A missing capability
 * (`UnsupportedAlgorithmException`: no ext-sodium, an OpenSSL build without the curve) is
 * `InvalidKeyMaterialException::unsupported`; any other crypto refusal becomes
 * `InvalidKeyMaterialException::wrongType` when the caller says what was wrong, and
 * propagates unchanged otherwise. The messages never carry key material.
 *
 * @internal
 */
final class CryptoErrors
{
    /**
     * @template T
     *
     * @param  Closure(): T  $operation
     * @return T
     */
    public static function translate(Algorithm $algorithm, Closure $operation, ?string $refusal = null): mixed
    {
        try {
            return $operation();
        } catch (UnsupportedAlgorithmException $exception) {
            throw InvalidKeyMaterialException::unsupported($algorithm, $exception);
        } catch (CryptoException $exception) {
            throw $refusal === null ? $exception : InvalidKeyMaterialException::wrongType($algorithm, $refusal, $exception);
        }
    }
}
