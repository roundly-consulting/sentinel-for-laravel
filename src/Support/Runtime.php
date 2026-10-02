<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Support;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use RoundlyConsulting\Sentinel\Exceptions\AcknowledgementDeniedException;

/**
 * Who is acting, and from where. Outside the console an acknowledgement needs an actor; in
 * the console (artisan, scheduled jobs) with nobody logged in it is recorded as the system.
 */
final readonly class Runtime
{
    public function __construct(
        private Application $app,
        private ?bool $console = null,
    ) {}

    public function inConsole(): bool
    {
        return $this->console ?? $this->app->runningInConsole();
    }

    /**
     * The authenticated user of the default guard, when it is a model.
     */
    public function user(): ?Model
    {
        if (! $this->app->bound('auth')) {
            return null;
        }

        $user = $this->app->make('auth')->guard()->user();

        return $user instanceof Model ? $user : null;
    }

    /**
     * The given actor, else the authenticated user; null (the system) only in the console.
     *
     * @throws AcknowledgementDeniedException
     */
    public function actor(?Model $actor): ?Model
    {
        $actor ??= $this->user();

        if ($actor === null && ! $this->inConsole()) {
            throw AcknowledgementDeniedException::actorRequired();
        }

        return $actor;
    }
}
