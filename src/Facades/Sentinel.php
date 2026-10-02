<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Facades;

use Closure;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Response as ClientResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Facade;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RoundlyConsulting\Sentinel\Accessors\IdempotencyAccessor;
use RoundlyConsulting\Sentinel\Accessors\KeysAccessor;
use RoundlyConsulting\Sentinel\Accessors\LedgerAccessor;
use RoundlyConsulting\Sentinel\Accessors\NoncesAccessor;
use RoundlyConsulting\Sentinel\Accessors\SignaturesAccessor;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\BaselineOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\CheckpointResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ConsumeNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\GeneratedKey;
use RoundlyConsulting\Sentinel\DataTransferObjects\GenerateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentCall;
use RoundlyConsulting\Sentinel\DataTransferObjects\IdempotentResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ImportKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssuedNonce;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssueNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\KeyInfo;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerFinding;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerVerifyOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\PruneResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealWhereRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RevokeKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotateKeyRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\RotationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\ScanReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\SignedRouteRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SigningOptions;
use RoundlyConsulting\Sentinel\DataTransferObjects\UpdateAndResealRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerifiedSignature;
use RoundlyConsulting\Sentinel\Enums\SignatureRejection;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;
use RoundlyConsulting\Sentinel\ModelSeals;
use RoundlyConsulting\Sentinel\SealHandle;
use RoundlyConsulting\Sentinel\SentinelManager;
use RoundlyConsulting\Sentinel\Testing\RecordedCall;
use RoundlyConsulting\Sentinel\Testing\SentinelFake;

/**
 * Import this class explicitly — Sentinel registers **no** global alias (cartalyst/sentinel
 * owns the global `Sentinel`, laravel/sentinel ships `Laravel\Sentinel\Sentinel`).
 *
 * @method static SealHandle for(Model $model, string|null $seal = null)
 * @method static ModelSeals model(string $class)
 * @method static list<class-string<Model>> sealables()
 * @method static SealResult seal(Model $model, string|null $seal = null, string|null $reason = null, Model|null $actor = null)
 * @method static VerificationResult verify(Model $model, string|null $seal = null)
 * @method static VerificationResult verifyOrFail(Model $model, string|null $seal = null)
 * @method static VerificationReport verifyAll(Model $model)
 * @method static VerificationReport verifyMany(iterable<Model> $models, string|null $seal = null)
 * @method static bool isIntact(Model $model)
 * @method static AcknowledgementResult acknowledge(Model $model, string $reason, Model|null $actor = null, string|null $seal = null)
 * @method static bool unseal(Model $model, string $reason, Model|null $actor = null, string|null $seal = null)
 * @method static list<LedgerRecord> ledgerHistory(Model $model, string|null $seal = null, int $limit = 50)
 * @method static SealRecord|null currentSeal(Model $model, string|null $seal = null)
 * @method static ScanReport scan(ScanOptions $options)
 * @method static ResealReport reseal(ResealOptions $options)
 * @method static ResealReport resealWhere(ResealWhereRequest $request)
 * @method static ResealReport updateAndReseal(UpdateAndResealRequest $request)
 * @method static ResealReport sealMissing(BaselineOptions $options)
 * @method static mixed withoutSealing(Closure $callback, string $reason)
 * @method static mixed withoutVerification(Closure $callback)
 * @method static KeysAccessor keys()
 * @method static GeneratedKey generateKey(GenerateKeyRequest $request)
 * @method static KeyInfo importKey(ImportKeyRequest $request)
 * @method static RotationResult rotateKey(RotateKeyRequest $request)
 * @method static KeyInfo revokeKey(RevokeKeyRequest $request)
 * @method static KeyInfo retireKey(string $ring, string $keyId)
 * @method static list<KeyInfo> listKeys(string|null $ring = null)
 * @method static KeyInfo|null findKey(string $ring, string $keyId)
 * @method static KeyInfo currentKey(string|null $ring = null)
 * @method static SentinelManager extend(string $driver, Closure $factory)
 * @method static LedgerAccessor ledger()
 * @method static CheckpointResult|null checkpoint(CheckpointOptions|null $options = null)
 * @method static LedgerReport verifyLedger(LedgerVerifyOptions|null $options = null)
 * @method static CheckpointRecord|null ledgerHead(string|null $connection = null)
 * @method static list<string> anchors()
 * @method static SentinelManager extendAnchor(string $driver, Closure $factory)
 * @method static IdempotencyAccessor idempotency()
 * @method static IdempotentResult runIdempotent(IdempotentCall $call)
 * @method static bool forgetIdempotencyKey(string $key, string $scope)
 * @method static NoncesAccessor nonces()
 * @method static IssuedNonce issueNonce(IssueNonceRequest $request)
 * @method static bool consumeNonce(ConsumeNonceRequest $request)
 * @method static string signedRoute(SignedRouteRequest $request)
 * @method static PruneResult prune(PruneOptions|null $options = null)
 * @method static SignaturesAccessor signatures()
 * @method static RequestInterface signRequest(RequestInterface $request, string $keyId, SigningOptions|null $options = null)
 * @method static VerifiedSignature verifyRequestSignature(Request $request, string|null $profile = null)
 * @method static VerifiedSignature verifyResponseSignature(ResponseInterface|ClientResponse $response, string|null $profile = null)
 * @method static SentinelFake fakeStatus(Model $model, VerificationStatus $status, string|null $seal = null, list<string>|null $changed = null)
 * @method static SentinelFake fakeVerifiedSignature(VerifiedSignature|null $signature = null)
 * @method static SentinelFake rejectSignatures(SignatureRejection $reason)
 * @method static SentinelFake fakeStatusOnce(Model $model, VerificationStatus $status, string|null $seal = null, list<string>|null $changed = null)
 * @method static SentinelFake fakeLedgerFindings(LedgerFinding ...$findings)
 * @method static void assertSealed(Model $model, string|null $seal = null, Closure|null $callback = null)
 * @method static void assertNotSealed(Model $model, string|null $seal = null)
 * @method static void assertNothingSealed()
 * @method static void assertVerified(Model $model, string|null $seal = null)
 * @method static void assertNothingVerified()
 * @method static void assertNotVerified(Model $model, string|null $seal = null)
 * @method static void assertAcknowledged(Model $model, string|null $reason = null)
 * @method static void assertNotAcknowledged(Model $model)
 * @method static void assertNothingAcknowledged()
 * @method static void assertUnsealed(Model $model, string|null $seal = null)
 * @method static void assertNothingUnsealed()
 * @method static void assertSealingSuspended(string|null $reason = null)
 * @method static void assertSealingNotSuspended()
 * @method static void assertScanned(string|null $model = null)
 * @method static void assertKeyGenerated(string|null $ring = null)
 * @method static void assertKeyImported(string|null $ring = null, string|null $keyId = null)
 * @method static void assertKeyRotated(string|null $ring = null)
 * @method static void assertKeyRevoked(string $keyId)
 * @method static void assertKeyRetired(string $keyId)
 * @method static void assertNoKeyChanges()
 * @method static void assertCheckpointed(int|null $times = null)
 * @method static void assertLedgerVerified()
 * @method static void assertResealed(string $model, int|null $count = null)
 * @method static void assertNothingResealed()
 * @method static void assertIdempotentRun(string $key, bool|null $replayed = null)
 * @method static void assertNoIdempotentRuns()
 * @method static void assertIdempotencyKeyForgotten(string $key)
 * @method static void assertNonceIssued(string $purpose)
 * @method static void assertNonceConsumed(string $purpose)
 * @method static void assertNoNoncesIssued()
 * @method static void assertNonceNotConsumed(string $purpose)
 * @method static void assertSingleUseUrlIssued(string|null $route = null)
 * @method static void assertPruned()
 * @method static void assertRequestSigned(string|null $keyId = null)
 * @method static void assertNothingSigned()
 * @method static void assertSignatureVerified(string|null $profile = null)
 * @method static list<RecordedCall> recorded(string|null $method = null)
 *
 * @see SentinelManager
 */
final class Sentinel extends Facade
{
    /**
     * Swap the manager for a recording fake — behind the facade and in the container, so an
     * injected SentinelManager is faked too.
     */
    public static function fake(): SentinelFake
    {
        $fake = app(SentinelFake::class);

        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return SentinelManager::class;
    }
}
