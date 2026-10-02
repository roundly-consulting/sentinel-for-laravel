<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Actions\Nonces;

use Illuminate\Routing\UrlGenerator;
use RoundlyConsulting\Sentinel\DataTransferObjects\IssueNonceRequest;
use RoundlyConsulting\Sentinel\DataTransferObjects\SignedRouteRequest;
use RoundlyConsulting\Sentinel\Nonces\NonceDigest;
use RoundlyConsulting\Sentinel\SentinelManager;

/**
 * A signed URL that works once: Laravel's temporary signed route plus a `_nonce` issued for
 * the route (purpose `url:<route name>`). The `sentinel.single-use` middleware checks the
 * signature, then consumes the nonce.
 */
final readonly class IssueSingleUseUrlAction
{
    public function __construct(
        private SentinelManager $manager,
        private UrlGenerator $urls,
    ) {}

    public function execute(SignedRouteRequest $request): string
    {
        $nonce = $this->manager->issueNonce(new IssueNonceRequest(NonceDigest::routePurpose($request->name), $request->ttl));

        return $this->urls->temporarySignedRoute($request->name, $nonce->expiresAt, [...$request->parameters, '_nonce' => $nonce->value]);
    }
}
