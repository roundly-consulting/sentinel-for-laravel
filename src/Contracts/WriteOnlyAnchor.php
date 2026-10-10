<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Contracts;

/**
 * An anchor nothing can be read back from (a log shipped elsewhere): its `latest()` is always
 * null. A checkpoint run with nothing pending republishes the newest checkpoint to every
 * anchor that holds nothing or an older one — but never to a write-only anchor, which would
 * receive it again on every run. Implement this on a custom write-only anchor.
 */
interface WriteOnlyAnchor extends Anchor {}
