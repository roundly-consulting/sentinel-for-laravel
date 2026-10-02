<?php

declare(strict_types=1);

return [
    'tampered' => 'The requested resource failed an integrity check.',

    'problems' => [
        'idempotency_key_missing' => [
            'title' => 'Idempotency key required',
            'detail' => 'This endpoint needs an Idempotency-Key header.',
        ],
        'invalid_idempotency_key' => [
            'title' => 'Invalid idempotency key',
            'detail' => 'The Idempotency-Key header is not a valid key.',
        ],
        'idempotency_key_reused' => [
            'title' => 'Idempotency key reused',
            'detail' => 'This idempotency key was already used with a different request.',
        ],
        'idempotency_request_in_progress' => [
            'title' => 'Request in progress',
            'detail' => 'A request with this idempotency key is still being processed. Retry later.',
        ],
        'idempotent_response_unavailable' => [
            'title' => 'Response unavailable',
            'detail' => 'A request with this idempotency key completed, but its response cannot be replayed.',
        ],
        'nonce_rejected' => [
            'title' => 'Link not valid',
            'detail' => 'This link or one-time token is invalid, expired or already used.',
        ],
        'signature_rejected' => [
            'title' => 'Signature rejected',
            'detail' => 'The request does not carry a valid HTTP message signature.',
        ],
    ],
];
