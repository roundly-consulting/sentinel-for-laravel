<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Encryption\MissingAppKeyException;
use RoundlyConsulting\Crypto\Aead\Aes256Gcm;
use RoundlyConsulting\Crypto\Aead\DecryptionFailedException;
use RoundlyConsulting\Crypto\Codec\Base64;
use RoundlyConsulting\Crypto\Codec\Base64Url;
use RoundlyConsulting\Crypto\Codec\InvalidEncodingException;
use RoundlyConsulting\Crypto\Hash\HashAlgorithm;
use SensitiveParameter;

/**
 * Sentinel's own encryption at rest — database key envelopes and stored idempotent responses:
 * AES-256-GCM (RFC 5116, crypto-for-laravel) under a key derived from `APP_KEY` with HKDF for
 * that one purpose, the record's identity as associated data.
 *
 * Never the application encrypter: its ciphertexts carry no purpose, so every `encrypted` cast
 * a host lets a user write would mint envelopes — and decrypt them for display. Here a
 * ciphertext opens only under its own purpose and its own identity; anything the application
 * encrypter produced never opens at all. Decrypts with `app.previous_keys` too (an `APP_KEY`
 * rotation); always encrypts with the current key.
 *
 * @internal
 */
final readonly class StorageCipher
{
    public const string KEY_ENVELOPE = 'key-envelope';

    public const string IDEMPOTENT_RESPONSE = 'idempotent-response';

    private const string PREFIX = 'sentinel:aes-256-gcm:';

    public function __construct(private Repository $config) {}

    public function encrypt(string $purpose, #[SensitiveParameter] string $plaintext, string $associatedData): string
    {
        return self::PREFIX.Base64Url::encode((new Aes256Gcm)->seal($this->keys($purpose)[0], $plaintext, $associatedData));
    }

    /**
     * @throws DecryptException when the payload is not this purpose's ciphertext for this
     *                          identity under any of the application keys
     */
    public function decrypt(string $purpose, string $payload, string $associatedData): string
    {
        if (! str_starts_with($payload, self::PREFIX)) {
            throw new DecryptException('The payload is not a Sentinel ciphertext.');
        }

        try {
            $sealed = Base64Url::decode(substr($payload, strlen(self::PREFIX)));
        } catch (InvalidEncodingException) {
            throw new DecryptException('The payload is not a Sentinel ciphertext.');
        }

        foreach ($this->keys($purpose) as $key) {
            try {
                return (new Aes256Gcm)->open($key, $sealed, $associatedData);
            } catch (DecryptionFailedException) {
                // The next (previous) application key.
            }
        }

        throw new DecryptException('The payload could not be authenticated.');
    }

    /**
     * One subkey per application key: the current one first, then `app.previous_keys`.
     *
     * @return non-empty-list<string>
     */
    private function keys(string $purpose): array
    {
        $current = $this->config->get('app.key');

        if (! is_string($current) || $current === '') {
            throw new MissingAppKeyException;
        }

        $previous = $this->config->get('app.previous_keys');
        $keys = [self::derive($current, $purpose)];

        foreach (is_array($previous) ? $previous : [] as $appKey) {
            if (is_string($appKey) && $appKey !== '') {
                $keys[] = self::derive($appKey, $purpose);
            }
        }

        return $keys;
    }

    private static function derive(#[SensitiveParameter] string $appKey, string $purpose): string
    {
        return Hkdf::derive(HashAlgorithm::Sha256, self::bytes($appKey), Aes256Gcm::KEY_BYTES, Hkdf::storageInfo($purpose));
    }

    private static function bytes(#[SensitiveParameter] string $appKey): string
    {
        if (! str_starts_with($appKey, 'base64:')) {
            return $appKey;
        }

        try {
            return Base64::decode(substr($appKey, 7));
        } catch (InvalidEncodingException) {
            // A malformed APP_KEY is still key material; Laravel's encrypter refuses it loudly.
            return $appKey;
        }
    }
}
