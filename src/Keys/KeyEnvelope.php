<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Encryption\DecryptException;
use JsonException;
use RoundlyConsulting\Sentinel\Canonical\Jcs;
use RoundlyConsulting\Sentinel\Exceptions\CorruptRecordException;
use RoundlyConsulting\Sentinel\Exceptions\KeyIntegrityException;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;

/**
 * The integrity-bound envelope of a database key (plan §4.4.9). The JCS plaintext binds
 * every field and is encrypted by {@see StorageCipher} — AES-256-GCM under a key derived from
 * APP_KEY for envelopes only (honouring `APP_PREVIOUS_KEYS` on decrypt), with the row's plain
 * columns as associated data. So no ciphertext the application encrypter made (an `encrypted`
 * cast a user can write) ever opens as an envelope, an envelope never decrypts through the
 * application encrypter, and one copied to another row does not open. Opening also checks that
 * every bound field equals the row's plain columns, so swapping a ring/kid/algorithm, replacing
 * a public key or flipping a status without re-encrypting is an integrity failure.
 *
 * @internal
 */
final readonly class KeyEnvelope
{
    public const string VERSION = 'sentinel.key/1';

    private const array MEMBERS = ['activates_at', 'alg', 'kid', 'material', 'owner', 'public', 'revoked_at', 'ring', 'signs_until', 'status', 'v', 'verifies_until'];

    public function __construct(private StorageCipher $cipher) {}

    public static function encode(EnvelopeData $data): string
    {
        return Jcs::encode([
            'activates_at' => Clock::iso($data->activatesAt),
            'alg' => $data->algorithm,
            'kid' => $data->keyId,
            'material' => $data->material,
            'owner' => $data->owner,
            'public' => $data->public,
            'revoked_at' => $data->revokedAt === null ? null : Clock::iso($data->revokedAt),
            'ring' => $data->ring,
            'signs_until' => $data->signsUntil === null ? null : Clock::iso($data->signsUntil),
            'status' => $data->status,
            'v' => self::VERSION,
            'verifies_until' => $data->verifiesUntil === null ? null : Clock::iso($data->verifiesUntil),
        ]);
    }

    /**
     * Write the data to the row: plain columns and the envelope together, never apart.
     */
    public function apply(Key $row, EnvelopeData $data): void
    {
        $row->ring = $data->ring;
        $row->kid = $data->keyId;
        $row->algorithm = $data->algorithm;
        $row->status = $data->status;
        $row->activates_at = $data->activatesAt;
        $row->signs_until = $data->signsUntil;
        $row->verifies_until = $data->verifiesUntil;
        $row->revoked_at = $data->revokedAt;
        // "<morph type>:<key>" — the key never contains the separator's last occurrence.
        $row->owner_type = $data->owner === null ? null : substr($data->owner, 0, (int) strrpos($data->owner, ':'));
        $row->owner_id = $data->owner === null ? null : substr($data->owner, (int) strrpos($data->owner, ':') + 1);
        $row->envelope = $this->cipher->encrypt(StorageCipher::KEY_ENVELOPE, self::encode($data), self::identity(
            $data->ring, $data->keyId, $data->algorithm, $data->status, $data->activatesAt, $data->signsUntil, $data->verifiesUntil,
            $data->revokedAt, $data->owner,
        ));
    }

    /**
     * The associated data an envelope is bound to: its row's plain columns.
     *
     * @throws KeyIntegrityException when a date column is unreadable
     */
    public static function associatedData(Key $row): string
    {
        try {
            return self::identity(
                (string) $row->ring, (string) $row->kid, (string) $row->algorithm, (string) $row->status, $row->activates_at,
                $row->signs_until, $row->verifies_until, $row->revoked_at,
                $row->owner_type === null ? null : $row->owner_type.':'.$row->owner_id,
            );
        } catch (CorruptRecordException) {
            throw KeyIntegrityException::envelopeMismatch((string) $row->getRawOriginal('ring'), (string) $row->getRawOriginal('kid'), 'dates');
        }
    }

    private static function identity(
        string $ring,
        string $keyId,
        string $algorithm,
        string $status,
        CarbonImmutable $activatesAt,
        ?CarbonImmutable $signsUntil,
        ?CarbonImmutable $verifiesUntil,
        ?CarbonImmutable $revokedAt,
        ?string $owner,
    ): string {
        return Jcs::encode([
            'activates_at' => Clock::iso($activatesAt),
            'alg' => $algorithm,
            'kid' => $keyId,
            'owner' => $owner,
            'revoked_at' => self::isoOrNull($revokedAt),
            'ring' => $ring,
            'signs_until' => self::isoOrNull($signsUntil),
            'status' => $status,
            'v' => self::VERSION,
            'verifies_until' => self::isoOrNull($verifiesUntil),
        ]);
    }

    /**
     * @throws KeyIntegrityException
     */
    public function open(Key $row): EnvelopeData
    {
        $ring = (string) $row->getRawOriginal('ring');
        $keyId = (string) $row->getRawOriginal('kid');

        try {
            $plaintext = $this->cipher->decrypt(StorageCipher::KEY_ENVELOPE, (string) $row->envelope, self::associatedData($row));
            $decoded = json_decode($plaintext, true, 4, JSON_THROW_ON_ERROR);
        } catch (DecryptException|JsonException) {
            throw KeyIntegrityException::envelopeMismatch($ring, $keyId, 'envelope');
        }

        if (! is_array($decoded) || array_keys($decoded) !== self::MEMBERS || $decoded['v'] !== self::VERSION) {
            throw KeyIntegrityException::envelopeMismatch($ring, $keyId, 'envelope');
        }

        $data = new EnvelopeData(
            self::string($decoded, 'ring', $ring, $keyId),
            self::string($decoded, 'kid', $ring, $keyId),
            self::string($decoded, 'alg', $ring, $keyId),
            self::nullableString($decoded, 'material', $ring, $keyId),
            self::nullableString($decoded, 'public', $ring, $keyId),
            self::string($decoded, 'status', $ring, $keyId),
            self::date($decoded, 'activates_at', $ring, $keyId) ?? throw KeyIntegrityException::envelopeMismatch($ring, $keyId, 'activates_at'),
            self::date($decoded, 'signs_until', $ring, $keyId),
            self::date($decoded, 'verifies_until', $ring, $keyId),
            self::date($decoded, 'revoked_at', $ring, $keyId),
            self::nullableString($decoded, 'owner', $ring, $keyId),
        );

        self::assertBound($row, $data);

        return $data;
    }

    private static function assertBound(Key $row, EnvelopeData $data): void
    {
        try {
            $columns = [
                'ring' => [$row->ring, $data->ring],
                'kid' => [$row->kid, $data->keyId],
                'algorithm' => [$row->algorithm, $data->algorithm],
                'status' => [$row->status, $data->status],
                'activates_at' => [Clock::iso($row->activates_at), Clock::iso($data->activatesAt)],
                'signs_until' => [self::isoOrNull($row->signs_until), self::isoOrNull($data->signsUntil)],
                'verifies_until' => [self::isoOrNull($row->verifies_until), self::isoOrNull($data->verifiesUntil)],
                'revoked_at' => [self::isoOrNull($row->revoked_at), self::isoOrNull($data->revokedAt)],
                'owner' => [$row->owner_type === null ? null : $row->owner_type.':'.$row->owner_id, $data->owner],
            ];
        } catch (CorruptRecordException) {
            throw KeyIntegrityException::envelopeMismatch($data->ring, $data->keyId, 'dates');
        }

        foreach ($columns as $field => [$column, $bound]) {
            if ($column !== $bound) {
                throw KeyIntegrityException::envelopeMismatch($data->ring, $data->keyId, $field);
            }
        }
    }

    private static function isoOrNull(?CarbonImmutable $at): ?string
    {
        return $at === null ? null : Clock::iso($at);
    }

    /**
     * @param  array<mixed>  $decoded
     */
    private static function string(array $decoded, string $member, string $ring, string $keyId): string
    {
        return is_string($decoded[$member]) ? $decoded[$member] : throw KeyIntegrityException::envelopeMismatch($ring, $keyId, $member);
    }

    /**
     * @param  array<mixed>  $decoded
     */
    private static function nullableString(array $decoded, string $member, string $ring, string $keyId): ?string
    {
        return $decoded[$member] === null ? null : self::string($decoded, $member, $ring, $keyId);
    }

    /**
     * @param  array<mixed>  $decoded
     */
    private static function date(array $decoded, string $member, string $ring, string $keyId): ?CarbonImmutable
    {
        $value = self::nullableString($decoded, $member, $ring, $keyId);

        if ($value === null) {
            return null;
        }

        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/D', $value) !== 1) {
            throw KeyIntegrityException::envelopeMismatch($ring, $keyId, $member);
        }

        return new CarbonImmutable(substr($value, 0, -1), 'UTC');
    }
}
