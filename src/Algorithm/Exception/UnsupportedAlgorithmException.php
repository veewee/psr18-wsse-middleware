<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm\Exception;

use RuntimeException;

/**
 * Raised when an algorithm is representable in the model but cannot be performed on this platform. We name
 * the algorithm and refuse rather than silently substitute a weaker one.
 */
final class UnsupportedAlgorithmException extends RuntimeException
{
    public static function forAlgorithm(string $algorithm): self
    {
        return new self('The algorithm "'.$algorithm.'" is not supported here.');
    }
}
