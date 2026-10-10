<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Builder;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Events\KeyRotated;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Exceptions\NoSigningKeyException;
use RoundlyConsulting\Sentinel\Keys\EnvelopeData;
use RoundlyConsulting\Sentinel\Keys\EnvSnippet;
use RoundlyConsulting\Sentinel\Keys\KeyIds;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Keys\SealingKey;
use RoundlyConsulting\Sentinel\Models\Key;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Rotate a ring's signing key, in the store the current key lives in.
 *
 *  - Database: a new active key; every older key of the ring that could still sign (the
 *    previous one, a pending one) stops signing when the new one activates (`signs_until`)
 *    and stays verify-only, so existing seals keep verifying.
 *  - Config: the environment lines for the new key plus the updated verify-only list.
 *  - A custom driver's key is refused (`KeyDriverException`): its own store rotates it.
 */
final readonly class RotateKeyAction
{
    /** Concurrent rotations of one ring can deadlock on MySQL's gap locks; the loser retries. */
    private const int ATTEMPTS = 10;

    public function __construct(
        private KeyStoreManager $keys,
        private Dispatcher $events,
    ) {}

    public function execute(RotateKeyRequest $request): RotationResult
    {
        $config = Settings::ring($request->ring);
        $current = $this->current($request->ring);
        $algorithm = $request->algorithm ?? $current?->algorithm() ?? $config->algorithm;

        if (! $config->allows($algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $algorithm);
        }

        // Only a config key is rotated by printing environment lines: a custom driver's key
        // would be printed as a "previous" entry (its secret) for a rotation that never happens.
        if ($current !== null && ! in_array($current->driver, ['database', 'config'], true)) {
            throw KeyDriverException::customDriver($request->ring, $current->driver);
        }

        $inDatabase = $current === null
            ? $this->keys->hasWritableStore($request->ring)
            : $current->driver === 'database';

        $result = $inDatabase
            ? $this->rotateDatabase($request, $algorithm)
            : $this->rotateConfig($request->ring, $config->previous, $algorithm, $current);

        $this->events->dispatch(new KeyRotated($request->ring, $result->current->keyId, $algorithm, $result->previous?->keyId));

        return $result;
    }

    /**
     * Under the row locks of every key of the ring that could still sign after the new one
     * activates — the current key, and a pending one an earlier scheduled rotation left — the
     * new key is stored and each of them stops signing when it activates. A concurrent rotation
     * waits for those locks and then demotes this one's key too, so one key signs at a time.
     */
    private function rotateDatabase(RotateKeyRequest $request, Algorithm $algorithm): RotationResult
    {
        $store = $this->keys->writableStore($request->ring);
        $activatesAt = $request->activatesAt ?? Clock::now();

        return (new Key)->getConnection()->transaction(function () use ($store, $request, $algorithm, $activatesAt): RotationResult {
            $signers = self::lockSigners($request->ring, $activatesAt);
            $current = $this->current($request->ring);
            $new = $store->insert(KeyIds::generate($request->ring), KeyMaterial::generate($algorithm), $activatesAt, null, null);

            foreach ($signers as $keyId) {
                $store->update($keyId, static fn (EnvelopeData $data): EnvelopeData => $data->with(signsUntil: $activatesAt));
            }

            $previous = $current === null ? null : $store->find($current->keyId);

            return new RotationResult(KeyInfo::fromKey($new), $previous === null ? null : KeyInfo::fromKey($previous));
        }, self::ATTEMPTS);
    }

    /**
     * Lock the ring's keys that may sign past `$at`. Waiting for a lock can end after another
     * rotation committed a key this read could not see yet: lock again until two reads agree.
     *
     * @return list<string>
     */
    private static function lockSigners(string $ring, CarbonImmutable $at): array
    {
        $locked = null;

        do {
            $previous = $locked;
            $locked = array_values(Key::query()
                ->where('ring', $ring)
                ->where('status', KeyStatus::Active->value)
                ->where(static fn (Builder $query) => $query->whereNull('signs_until')->orWhere('signs_until', '>', Clock::database($at)))
                ->orderBy('id')
                ->lockForUpdate()
                ->pluck('kid')
                ->map(static fn (mixed $kid): string => (string) $kid)
                ->all());
        } while ($locked !== $previous);

        return $locked;
    }

    private function rotateConfig(string $ring, string $previous, Algorithm $algorithm, ?SealingKey $current): RotationResult
    {
        $keyId = KeyIds::generate($ring);
        $material = KeyMaterial::generate($algorithm);
        $entries = Identifiers::csv($previous);

        if ($current !== null) {
            $entries[] = EnvSnippet::entry($current->keyId, $current->material());
        }

        return new RotationResult(
            new KeyInfo($ring, $keyId, $algorithm, KeyStatus::Active, 'config', true),
            $current === null ? null : new KeyInfo($ring, $current->keyId, $current->algorithm(), KeyStatus::VerifyOnly, 'config', false),
            EnvSnippet::forKey($ring, $keyId, $material, clearPublic: $current?->material()->encodedPublic() !== null)."\n".EnvSnippet::previous($ring, $entries),
        );
    }

    private function current(string $ring): ?SealingKey
    {
        try {
            return $this->keys->signingKey($ring);
        } catch (NoSigningKeyException) {
            return null;
        }
    }
}
