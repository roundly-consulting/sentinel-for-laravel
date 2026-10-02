<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Engine;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Enums\Algorithm;
use RoundlyConsulting\Sentinel\Enums\VerificationContext;
use RoundlyConsulting\Sentinel\Enums\VerificationStatus;

/**
 * The verdict being assembled for one (model, seal), so every status carries the same
 * identity and whatever is known so far.
 *
 * @internal
 */
final readonly class Outcome
{
    public function __construct(
        public Model $model,
        public string $seal,
        public VerificationContext $context,
        public bool $outdatedIsIntact,
        public ?int $version = null,
        public ?string $ring = null,
        public ?string $keyId = null,
        public ?Algorithm $algorithm = null,
        public ?CarbonImmutable $sealedAt = null,
    ) {}

    public function withRow(int $version, string $ring, string $keyId): self
    {
        return new self($this->model, $this->seal, $this->context, $this->outdatedIsIntact, $version, $ring, $keyId);
    }

    public function withAlgorithm(Algorithm $algorithm, ?CarbonImmutable $sealedAt = null): self
    {
        return new self($this->model, $this->seal, $this->context, $this->outdatedIsIntact, $this->version, $this->ring, $this->keyId, $algorithm, $sealedAt ?? $this->sealedAt);
    }

    /**
     * @param  list<string>|null  $changed
     */
    public function result(VerificationStatus $status, ?string $reason = null, ?array $changed = null, ?int $ledgerVersion = null): VerificationResult
    {
        return new VerificationResult(
            $status, $reason, $this->model->getMorphClass(), $this->model->getKey(), $this->seal, $this->version, $ledgerVersion,
            $this->ring, $this->keyId, $this->algorithm, $this->sealedAt, $changed, $this->context, $this->outdatedIsIntact,
        );
    }
}
