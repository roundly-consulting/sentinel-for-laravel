<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Keys;

use Illuminate\Contracts\Events\Dispatcher;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\Enums\KeyDestination;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Events\KeyGenerated;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Keys\EnvSnippet;
use RoundlyConsulting\Sentinel\Keys\KeyIds;
use RoundlyConsulting\Sentinel\Keys\KeyMaterial;
use RoundlyConsulting\Sentinel\Keys\KeyStoreManager;
use RoundlyConsulting\Sentinel\Support\Clock;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * Generate a key from the CSPRNG. A config destination returns the environment lines (the
 * material leaves the process exactly once, through the caller); a database destination
 * stores the encrypted envelope and returns only public information.
 */
final readonly class GenerateKeyAction
{
    public function __construct(
        private KeyStoreManager $keys,
        private Dispatcher $events,
    ) {}

    public function execute(GenerateKeyRequest $request): GeneratedKey
    {
        $config = Settings::ring($request->ring);

        if (! $config->allows($request->algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $request->algorithm);
        }

        $keyId = $request->keyId ?? KeyIds::generate($request->ring);

        if (! Identifiers::isKeyId($keyId)) {
            throw KeyDriverException::invalidKeyId($request->ring);
        }

        if ($request->label !== null && (! mb_check_encoding($request->label, 'UTF-8') || mb_strlen($request->label) > 191)) {
            throw KeyDriverException::invalidLabel();
        }

        if ($this->keys->find($request->ring, $keyId) !== null) {
            throw KeyDriverException::keyIdTaken($request->ring, $keyId);
        }

        $material = KeyMaterial::generate($request->algorithm);

        if ($request->destination === KeyDestination::Config) {
            $this->events->dispatch(new KeyGenerated($request->ring, $keyId, $request->algorithm));

            return new GeneratedKey(
                new KeyInfo($request->ring, $keyId, $request->algorithm, KeyStatus::Active, 'config', true),
                EnvSnippet::forKey($request->ring, $keyId, $material),
                $material->encodedPublic(),
            );
        }

        $key = $this->keys->writableStore($request->ring)->insert(
            $keyId, $material, $request->activatesAt ?? Clock::now(), $request->owner, $request->label,
        );

        $this->events->dispatch(new KeyGenerated($request->ring, $keyId, $request->algorithm));

        return new GeneratedKey(KeyInfo::fromKey($key), null, $material->encodedPublic());
    }
}
