<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Testing;

use Closure;
use Illuminate\Contracts\Container\Container;
use PHPUnit\Framework\Assert as PHPUnit;
use RoundlyConsulting\Sentinel\DataTransferObjects\ExampleSentinelData;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\Enums\KeyStatus;
use RoundlyConsulting\Sentinel\Exceptions\AlgorithmNotAllowedException;
use RoundlyConsulting\Sentinel\Exceptions\KeyDriverException;
use RoundlyConsulting\Sentinel\Keys\KeyIds;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Support\Identifiers;
use RoundlyConsulting\Sentinel\Support\Settings;

/**
 * The test double installed by `Sentinel::fake()`. It extends the manager, so injected
 * managers keep type-checking, and records every mutating call — including those made
 * through sub-accessors and model traits — instead of touching keys, seals or the ledger.
 *
 * Same semantics where it matters (fleet theme 7): unknown rings, disallowed algorithms and
 * missing reasons throw exactly what production throws. No key material is ever needed.
 */
final class SentinelFake extends SentinelManager
{
    /** @var list<RecordedCall> */
    private array $calls = [];

    public function __construct(Container $container)
    {
        parent::__construct($container);
    }

    public function example(ExampleSentinelData $data): string
    {
        $this->record('example', $data, '');

        // Nothing ran, so there is nothing real to return — a canned value keeps the type.
        return '';
    }

    public function generateKey(GenerateKeyRequest $request): GeneratedKey
    {
        $config = Settings::ring($request->ring);

        if (! $config->allows($request->algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $request->algorithm);
        }

        $keyId = $request->keyId ?? KeyIds::generate($request->ring);

        if (! Identifiers::isKeyId($keyId)) {
            throw KeyDriverException::invalidKeyId($request->ring);
        }

        $result = new GeneratedKey(new KeyInfo(
            $request->ring, $keyId, $request->algorithm, KeyStatus::Active, $request->destination->value, true,
            $request->activatesAt, label: $request->label,
        ));

        return $this->record('generateKey', $request, $result);
    }

    public function rotateKey(RotateKeyRequest $request): RotationResult
    {
        $config = Settings::ring($request->ring);
        $algorithm = $request->algorithm ?? $config->algorithm;

        if (! $config->allows($algorithm)) {
            throw AlgorithmNotAllowedException::forRing($request->ring, $algorithm);
        }

        $result = new RotationResult(new KeyInfo(
            $request->ring, KeyIds::generate($request->ring), $algorithm, KeyStatus::Active, $config->driver, true, $request->activatesAt,
        ));

        return $this->record('rotateKey', $request, $result);
    }

    public function revokeKey(RevokeKeyRequest $request): KeyInfo
    {
        $config = Settings::ring($request->ring);
        $reason = trim($request->reason);

        if ($reason === '' || mb_strlen($reason) > 1000) {
            throw KeyDriverException::reasonRequired();
        }

        return $this->record('revokeKey', $request, new KeyInfo(
            $request->ring, $request->keyId, $config->algorithm, KeyStatus::Revoked, $config->driver, false,
        ));
    }

    public function retireKey(string $ring, string $keyId): KeyInfo
    {
        $config = Settings::ring($ring);

        return $this->record('retireKey', [$ring, $keyId], new KeyInfo(
            $ring, $keyId, $config->algorithm, KeyStatus::Retired, $config->driver, false,
        ));
    }

    // ── assertions ────────────────────────────────────────────────────────────

    /**
     * @param  (Closure(ExampleSentinelData): bool)|null  $callback
     */
    public function assertExampleCalled(?Closure $callback = null): void
    {
        $matching = array_filter(
            $this->recorded('example'),
            static fn (RecordedCall $call): bool => $callback === null || ($call->arguments instanceof ExampleSentinelData && $callback($call->arguments)),
        );

        PHPUnit::assertNotEmpty($matching, $callback === null
            ? 'Expected example() to be called, but it was not.'
            : 'Expected example() to be called with matching data, but no call matched.');
    }

    public function assertNothingCalled(): void
    {
        PHPUnit::assertEmpty(
            $this->calls,
            sprintf('Expected nothing to be called, but %d call(s) were recorded.', count($this->calls)),
        );
    }

    public function assertKeyGenerated(?string $ring = null): void
    {
        PHPUnit::assertNotEmpty(
            $this->keyCalls('generateKey', $ring),
            $ring === null ? 'Expected a key to be generated, but none was.' : "Expected a key to be generated in ring [{$ring}], but none was.",
        );
    }

    public function assertKeyRotated(?string $ring = null): void
    {
        PHPUnit::assertNotEmpty(
            $this->keyCalls('rotateKey', $ring),
            $ring === null ? 'Expected a key rotation, but none happened.' : "Expected ring [{$ring}] to be rotated, but it was not.",
        );
    }

    public function assertKeyRevoked(string $keyId): void
    {
        $matching = array_filter(
            $this->recorded('revokeKey'),
            static fn (RecordedCall $call): bool => $call->arguments instanceof RevokeKeyRequest && $call->arguments->keyId === $keyId,
        );

        PHPUnit::assertNotEmpty($matching, "Expected key [{$keyId}] to be revoked, but it was not.");
    }

    public function assertNoKeyChanges(): void
    {
        $changes = array_merge(...array_map($this->recorded(...), ['generateKey', 'rotateKey', 'revokeKey', 'retireKey']));

        PHPUnit::assertEmpty($changes, sprintf('Expected no key changes, but %d were recorded.', count($changes)));
    }

    /**
     * The recorded calls, optionally of one manager method.
     *
     * @return list<RecordedCall>
     */
    public function recorded(?string $method = null): array
    {
        return array_values(array_filter(
            $this->calls,
            static fn (RecordedCall $call): bool => $method === null || $call->method === $method,
        ));
    }

    /**
     * @return list<RecordedCall>
     */
    private function keyCalls(string $method, ?string $ring): array
    {
        return array_values(array_filter(
            $this->recorded($method),
            static fn (RecordedCall $call): bool => $ring === null
                || (($call->arguments instanceof GenerateKeyRequest || $call->arguments instanceof RotateKeyRequest) && $call->arguments->ring === $ring),
        ));
    }

    /**
     * @template TResult
     *
     * @param  object|list<mixed>  $arguments
     * @param  TResult  $result
     * @return TResult
     */
    private function record(string $method, object|array $arguments, mixed $result): mixed
    {
        $this->calls[] = new RecordedCall($method, $arguments, $result);

        return $result;
    }
}
