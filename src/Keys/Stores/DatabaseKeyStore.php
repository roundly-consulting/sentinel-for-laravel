<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Keys\Stores;

use Carbon\CarbonImmutable;
use Closure;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use RoundlyConsulting\Sentinel\Contracts\KeyStore;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Events\KeyIntegrityViolated;
use RoundlyConsulting\Sentinel\Exceptions\InvalidKeyMaterialException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\KeyIntegrityException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Exceptions\UnknownKeyException;
use RoundlyConsulting\Sentinel\Keys\EnvelopeData;
use RoundlyConsulting\Sentinel\Keys\KeyCache;
use RoundlyConsulting\Sentinel\Keys\KeyEnvelope;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyReseal;
use RoundlyConsulting\Sentinel\Keys\KeyStatusResolver;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Settings;
use SensitiveParameter;

/**
 * Keys in `sentinel_keys`, each row an encrypted, integrity-bound envelope (plan §4.4.9) that
 * binds its label too ({@see KeyEnvelope}).
 * Decrypted keys are memoized for the current request only (this store lives in the scoped
 * {@see KeyCache}). A row that fails its integrity check is treated as unknown and reported
 * through {@see KeyIntegrityViolated}.
 *
 * @internal
 */
final class DatabaseKeyStore implements KeyStore
{
    /** @var array<string, SealingKey|null> */
    private array $loaded = [];

    /**
     * @param  list<string>  $revoked
     */
    public function __construct(
        private readonly string $ring,
        private readonly array $revoked,
        private readonly KeyCache $cache,
        private readonly Dispatcher $events,
        private readonly KeyEnvelope $envelope,
    ) {}

    public function signingKey(): SealingKey
    {
        $rows = Key::query()
            ->where('ring', $this->ring)
            ->where('status', KeyStatus::Active->value)
            ->orderByDesc('activates_at')
            ->orderByDesc('id')
            ->get();

        foreach ($rows as $row) {
            $key = $this->open($row);

            if ($key?->canSign()) {
                return $key;
            }
        }

        throw NoSigningKeyException::forRing($this->ring);
    }

    public function find(string $keyId): ?SealingKey
    {
        if (array_key_exists($keyId, $this->loaded)) {
            return $this->loaded[$keyId];
        }

        $row = Key::query()->where('ring', $this->ring)->where('kid', $keyId)->first();

        return $row === null ? null : $this->open($row);
    }

    public function all(): array
    {
        $keys = [];

        foreach (Key::query()->where('ring', $this->ring)->orderBy('activates_at')->orderBy('id')->get() as $row) {
            $key = $this->open($row);

            if ($key !== null) {
                $keys[] = KeyInfo::fromKey($key);
            }
        }

        return $keys;
    }

    public function supportsWrites(): bool
    {
        return true;
    }

    /**
     * Store a new key (its envelope and query columns together). The manual status and the
     * label are bound into the envelope: an imported partner key stays verify-only, and its
     * label is the one it was stored with.
     */
    public function insert(string $keyId, #[SensitiveParameter] KeyMaterial $material, CarbonImmutable $activatesAt, ?Model $owner, ?string $label, KeyStatus $status = KeyStatus::Active): SealingKey
    {
        $row = new Key;

        $this->envelope->apply($row, new EnvelopeData(
            $this->ring, $keyId, $material->algorithm->value, $material->encodedPrivate(), $material->encodedPublic(),
            $status->value, $activatesAt, owner: $owner === null ? null : $owner->getMorphClass().':'.$owner->getKey(), label: $label,
        ));

        try {
            $row->save();
        } catch (UniqueConstraintViolationException) {
            throw KeyDriverException::keyIdTaken($this->ring, $keyId);
        }

        unset($this->loaded[$keyId]);

        return $this->open($row) ?? throw KeyIntegrityException::envelopeMismatch($this->ring, $keyId, 'envelope');
    }

    /**
     * Change a stored key under a row lock (no lost updates), re-encrypting its envelope — in
     * the current format, so a legacy row's label is bound from here on.
     *
     * @param  Closure(EnvelopeData): EnvelopeData  $change
     */
    public function update(string $keyId, Closure $change, ?string $revocationReason = null): SealingKey
    {
        return (new Key)->getConnection()->transaction(function () use ($keyId, $change, $revocationReason): SealingKey {
            $row = Key::query()->where('ring', $this->ring)->where('kid', $keyId)->lockForUpdate()->first()
                ?? throw UnknownKeyException::inRing($this->ring, $keyId);

            $this->envelope->apply($row, $change($this->envelope->open($row)));

            if ($revocationReason !== null) {
                $row->revocation_reason = $revocationReason;
            }

            $row->save();
            unset($this->loaded[$keyId]);

            return $this->open($row) ?? throw KeyIntegrityException::envelopeMismatch($this->ring, $keyId, 'envelope');
        });
    }

    /**
     * Re-seal a stored key in the current envelope format, under its row lock
     * (`sentinel:key:reseal`): the label its column holds now is bound from here on. A row
     * that already binds its label is left alone; one that fails its integrity check — or a
     * legacy one `sentinel.keys.require_bound_label` refuses — is never re-sealed, and is
     * reported like any read of it. Nor is a legacy one whose label is not UTF-8 (only SQLite
     * stores one): no envelope can bind it. `$before` sees the outcome before anything is written.
     *
     * @param  Closure(KeyReseal): void  $before
     */
    public function reseal(string $keyId, bool $dryRun, Closure $before): KeyReseal
    {
        return (new Key)->getConnection()->transaction(function () use ($keyId, $dryRun, $before): KeyReseal {
            $row = Key::query()->where('ring', $this->ring)->where('kid', $keyId)->lockForUpdate()->first()
                ?? throw UnknownKeyException::inRing($this->ring, $keyId);
            $version = $this->envelope->version($row);

            $result = match (true) {
                $version === KeyEnvelope::VERSION => new KeyReseal($this->ring, $keyId, KeyReseal::CURRENT, $row->label),
                $version === null => new KeyReseal($this->ring, $keyId, KeyReseal::FAILED),
                Settings::requireBoundLabel() => new KeyReseal($this->ring, $keyId, KeyReseal::REFUSED),
                $row->label !== null && ! mb_check_encoding($row->label, 'UTF-8') => new KeyReseal($this->ring, $keyId, KeyReseal::UNBINDABLE, $row->label),
                default => new KeyReseal($this->ring, $keyId, KeyReseal::RESEALED, $row->label),
            };

            if ($result->failsIntegrity()) {
                $this->violated($keyId);
            }

            $before($result);

            if ($result->outcome === KeyReseal::RESEALED && ! $dryRun) {
                $this->envelope->apply($row, $this->envelope->open($row));
                $row->save();
                unset($this->loaded[$keyId]);
            }

            return $result;
        });
    }

    private function open(Key $row): ?SealingKey
    {
        $keyId = (string) $row->getRawOriginal('kid');

        try {
            $data = $this->envelope->open($row);
            $material = KeyMaterial::fromEncoded(
                Algorithm::tryFrom($data->algorithm) ?? throw KeyIntegrityException::envelopeMismatch($this->ring, $keyId, 'algorithm'),
                $data->material,
                $data->public,
            );
        } catch (KeyIntegrityException|InvalidKeyMaterialException) {
            $this->violated($keyId);

            return $this->loaded[$keyId] = null;
        }

        $status = KeyStatusResolver::resolve(
            $this->ring, $keyId, $this->revoked, Clock::now(), KeyStatus::tryFrom($data->status) ?? KeyStatus::Revoked,
            $data->activatesAt, $data->signsUntil, $data->verifiesUntil, $data->revokedAt, ! $material->canSign(),
        );

        $ownerType = $data->owner === null ? null : substr($data->owner, 0, (int) strrpos($data->owner, ':'));
        $ownerId = $data->owner === null ? null : substr($data->owner, (int) strrpos($data->owner, ':') + 1);

        return $this->loaded[$keyId] = new SealingKey(
            $this->ring, $keyId, $material, $status, 'database', $data->activatesAt, $data->signsUntil,
            $data->verifiesUntil, $data->revokedAt, $data->label, $ownerType, $ownerId,
        );
    }

    /**
     * A row failed its integrity check: the key is unknown for this request, and the host hears of it.
     */
    private function violated(string $keyId): void
    {
        $this->cache->markIntegrityFailure($this->ring, $keyId);
        $this->events->dispatch(new KeyIntegrityViolated($this->ring, $keyId, 'database'));
    }
}
