<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use Illuminate\Contracts\Events\Dispatcher;
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
 *  - Database: a new active key; the previous one stops signing when the new one activates
 *    (`signs_until`) and stays verify-only, so existing seals keep verifying.
 *  - Config: the environment lines for the new key plus the updated verify-only list.
 *  - A custom driver's key is refused (`KeyDriverException`): its own store rotates it.
 */
final readonly class RotateKeyAction
{
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
            ? $this->rotateDatabase($request, $algorithm, $current)
            : $this->rotateConfig($request->ring, $config->previous, $algorithm, $current);

        $this->events->dispatch(new KeyRotated($request->ring, $result->current->keyId, $algorithm, $current?->keyId));

        return $result;
    }

    private function rotateDatabase(RotateKeyRequest $request, Algorithm $algorithm, ?SealingKey $current): RotationResult
    {
        $store = $this->keys->writableStore($request->ring);
        $activatesAt = $request->activatesAt ?? Clock::now();

        return (new Key)->getConnection()->transaction(static function () use ($store, $request, $algorithm, $activatesAt, $current): RotationResult {
            $new = $store->insert(KeyIds::generate($request->ring), KeyMaterial::generate($algorithm), $activatesAt, null, null);

            $previous = $current === null
                ? null
                : $store->update($current->keyId, static fn (EnvelopeData $data): EnvelopeData => $data->with(signsUntil: $activatesAt));

            return new RotationResult(KeyInfo::fromKey($new), $previous === null ? null : KeyInfo::fromKey($previous));
        });
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
