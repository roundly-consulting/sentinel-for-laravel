<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Context
    |--------------------------------------------------------------------------
    |
    | An application-level domain separator bound into every seal, ledger entry,
    | checkpoint and field tag. Two applications that share signing keys but use
    | different contexts can never forge each other's seals. Changing it
    | invalidates every existing seal — re-seal with `sentinel:reseal`.
    |
    */

    'context' => env('SENTINEL_CONTEXT', ''),

];
