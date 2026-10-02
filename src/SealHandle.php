<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgementResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\LedgerRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealRecord;
use RoundlyConsulting\Sentinel\DataTransferObjects\SealResult;
use RoundlyConsulting\Sentinel\DataTransferObjects\VerificationResult;
use RoundlyConsulting\Sentinel\Definition\CompiledSeal;

/**
 * `Sentinel::for($invoice, 'financial')` — one seal of one model. `by()` and `because()`
 * return new handles; every call goes through the manager.
 */
final readonly class SealHandle
{
    public function __construct(
        private SentinelManager $manager,
        private Model $model,
        private CompiledSeal $seal,
        private ?string $reason = null,
        private ?Model $actor = null,
    ) {}

    public function by(?Model $actor): self
    {
        return new self($this->manager, $this->model, $this->seal, $this->reason, $actor);
    }

    public function because(string $reason): self
    {
        return new self($this->manager, $this->model, $this->seal, $reason, $this->actor);
    }

    public function name(): string
    {
        return $this->seal->name;
    }

    public function definition(): CompiledSeal
    {
        return $this->seal;
    }

    public function seal(): SealResult
    {
        return $this->manager->seal($this->model, $this->seal->name, $this->reason, $this->actor);
    }

    public function verify(): VerificationResult
    {
        return $this->manager->verify($this->model, $this->seal->name);
    }

    public function verifyOrFail(): VerificationResult
    {
        return $this->manager->verifyOrFail($this->model, $this->seal->name);
    }

    /**
     * This seal only (`$model->isIntact()` covers every seal).
     */
    public function isIntact(): bool
    {
        return $this->verify()->isIntact();
    }

    public function acknowledge(?string $reason = null): AcknowledgementResult
    {
        return $this->manager->acknowledge($this->model, (string) ($reason ?? $this->reason), $this->actor, $this->seal->name);
    }

    public function unseal(?string $reason = null): bool
    {
        return $this->manager->unseal($this->model, (string) ($reason ?? $this->reason), $this->actor, $this->seal->name);
    }

    public function current(): ?SealRecord
    {
        return $this->manager->currentSeal($this->model, $this->seal->name);
    }

    /**
     * @return list<LedgerRecord>
     */
    public function history(int $limit = 50): array
    {
        return $this->manager->ledgerHistory($this->model, $this->seal->name, $limit);
    }
}
