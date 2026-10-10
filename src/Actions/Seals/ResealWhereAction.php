<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Seals;

use Illuminate\Database\Eloquent\Collection;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealReport;
use RoundlyConsulting\Sentinel\DataTransferObjects\ResealWhereRequest;
use RoundlyConsulting\Sentinel\Definition\DefinitionRegistry;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;
use RoundlyConsulting\Sentinel\Exceptions\SentinelException;
use RoundlyConsulting\Sentinel\Support\BulkQuery;
use RoundlyConsulting\Sentinel\Support\Reasons;
use RoundlyConsulting\Sentinel\Support\Runtime;
use RoundlyConsulting\Sentinel\Support\SealingScope;

/**
 * A bulk acknowledgement: every row the query selects is acknowledged like
 * `Sentinel::acknowledge()` — intact rows are untouched, the others are re-sealed with the
 * reason, actor, previous status and changed attributes in their MAC'd ledger entries. A
 * policy denial stops the run; any other per-row failure is counted.
 */
final readonly class ResealWhereAction
{
    public function __construct(
        private DefinitionRegistry $registry,
        private AcknowledgeTamperingAction $acknowledge,
        private Runtime $runtime,
        private SealingScope $scope,
    ) {}

    public function execute(ResealWhereRequest $request): ResealReport
    {
        $compiled = $this->registry->for($request->model);
        $seals = $request->seal === null ? $compiled->all() : [$compiled->get($request->seal)];
        $reason = Reasons::normalize($request->reason);
        $actor = $this->runtime->actor($request->actor);
        $query = BulkQuery::resolve($request->model, $request->query);
        $tally = ['acknowledged' => 0, 'skipped' => 0, 'failed' => 0];

        $this->scope->withoutVerification(function () use ($query, $request, $seals, $reason, $actor, &$tally): void {
            // Paged by key: a caller's order would stay the primary sort and skip or repeat rows.
            $query->reorder()->chunkById(max(1, $request->chunk), function (Collection $models) use ($seals, $reason, $actor, &$tally): void {
                foreach ($models as $model) {
                    foreach ($seals as $seal) {
                        try {
                            $tally[$this->acknowledge->execute(new AcknowledgeRequest($model, $seal->name, $reason, $actor))->acknowledged ? 'acknowledged' : 'skipped']++;
                        } catch (AcknowledgementDeniedException $exception) {
                            throw $exception;
                        } catch (SentinelException) {
                            $tally['failed']++;
                        }
                    }
                }
            });
        });

        return new ResealReport(acknowledged: $tally['acknowledged'], skipped: $tally['skipped'], failed: $tally['failed']);
    }
}
