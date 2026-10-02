<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel;

use Illuminate\Contracts\Container\Container;
use RoundlyConsulting\Sentinel\Actions\ExampleSentinelAction;
use RoundlyConsulting\Sentinel\DataTransferObjects\ExampleSentinelData;

/**
 * The package's public API: the root behind the Sentinel facade, injectable by its
 * own class-string. Bound as a singleton in SentinelServiceProvider::register().
 *
 * Follows the `laravel-package-developer` skill section
 * "Public API: Actions → Manager → Facade (REQUIRED)":
 *
 *  - Every method is thin — resolve one action through the container and call `execute()`.
 *    Never `new` an action, so host container overrides and the fake both apply.
 *  - Flat methods for the core verbs; a small `final readonly` sub-accessor per sub-area once
 *    there are two or more; `for($model)` for a model-scoped handle.
 *  - Every host-facing action (no `@internal`) must be reachable from here.
 *  - Model traits and model methods call this manager (`app(SentinelManager::class)`),
 *    never an action — so the fake sees them too.
 *
 * Not final on purpose: SentinelFake extends it, so code that constructor-injects this
 * class still type-checks under `Sentinel::fake()`. The arch test exempts it from
 * `finalByDefault` by name.
 *
 * Exempt shapes — a pure trait, a per-request static builder, package-author or dev-only
 * tooling — have no host-facing stateful behaviour: delete this manager, the facade, the fake,
 * the example action and FacadeTest, and say why in one README line.
 */
class SentinelManager
{
    public function __construct(
        protected readonly Container $container,
    ) {}

    /**
     * REPLACE ME — rename after the real verb the action performs.
     */
    public function example(ExampleSentinelData $data): string
    {
        return $this->container->make(ExampleSentinelAction::class)->execute($data);
    }
}
