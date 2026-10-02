<?php

declare(strict_types=1);

return [
    'tampered' => 'Požadovaný zdroj neprešiel kontrolou integrity.',

    'problems' => [
        'idempotency_key_missing' => [
            'title' => 'Chýba kľúč idempotencie',
            'detail' => 'Tento endpoint vyžaduje hlavičku Idempotency-Key.',
        ],
        'invalid_idempotency_key' => [
            'title' => 'Neplatný kľúč idempotencie',
            'detail' => 'Hlavička Idempotency-Key neobsahuje platný kľúč.',
        ],
        'idempotency_key_reused' => [
            'title' => 'Kľúč idempotencie už bol použitý',
            'detail' => 'Tento kľúč idempotencie už bol použitý s inou požiadavkou.',
        ],
        'idempotency_request_in_progress' => [
            'title' => 'Požiadavka sa spracúva',
            'detail' => 'Požiadavka s týmto kľúčom idempotencie sa ešte spracúva. Skúste to neskôr.',
        ],
        'idempotent_response_unavailable' => [
            'title' => 'Odpoveď nie je k dispozícii',
            'detail' => 'Požiadavka s týmto kľúčom idempotencie bola dokončená, jej odpoveď však nemožno zopakovať.',
        ],
        'nonce_rejected' => [
            'title' => 'Neplatný odkaz',
            'detail' => 'Tento odkaz alebo jednorazový token je neplatný, expirovaný alebo už bol použitý.',
        ],
        'signature_rejected' => [
            'title' => 'Podpis bol odmietnutý',
            'detail' => 'Požiadavka nemá platný podpis HTTP správy.',
        ],
    ],
];
