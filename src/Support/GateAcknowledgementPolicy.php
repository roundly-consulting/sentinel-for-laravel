<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Contracts\Auth\Access\Gate;
use RoundlyConsulting\Sentinel\Contracts\AcknowledgementPolicy;
use RoundlyConsulting\Sentinel\DataTransferObjects\AcknowledgeRequest;

/**
 * The default policy: when `sentinel.acknowledgement.ability` is set, the actor must pass
 * that Gate ability for `[$model, $seal]`; otherwise any actor may acknowledge (a reason is
 * still required and recorded).
 */
final readonly class GateAcknowledgementPolicy implements AcknowledgementPolicy
{
    public function __construct(private Gate $gate) {}

    public function authorize(AcknowledgeRequest $request): ?string
    {
        $ability = Settings::acknowledgementAbility();

        if ($ability === null) {
            return null;
        }

        return $this->gate->forUser($request->actor)->allows($ability, [$request->model, $request->seal]) ? null : 'unauthorized';
    }
}
