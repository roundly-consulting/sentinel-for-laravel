<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Http\Exceptions;

use RoundlyConsulting\Sentinel\Exceptions\TamperedModelException;
use RoundlyConsulting\Sentinel\Support\Settings;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * `sentinel.verified` refused a request because a route model is not intact. The status is
 * `sentinel.middleware.verified_status` (409 by default) and the message is generic and
 * translated — the client never learns which status or reason was found (no verification
 * oracle). The finding itself is the previous exception, for the host's logs.
 */
final class SealVerificationFailedHttpException extends HttpException
{
    public static function forFinding(TamperedModelException $finding): self
    {
        $message = trans('sentinel::messages.tampered');

        return new self(Settings::verifiedStatus(), is_string($message) ? $message : 'The requested resource failed an integrity check.', $finding);
    }
}
