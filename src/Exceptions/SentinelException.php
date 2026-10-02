<?php

declare(strict_types=1);

namespace RoundlyConsulting\Sentinel\Exceptions;

use RuntimeException;

/**
 * The base of every exception Sentinel throws, so a host can catch the package as a whole.
 */
abstract class SentinelException extends RuntimeException {}
