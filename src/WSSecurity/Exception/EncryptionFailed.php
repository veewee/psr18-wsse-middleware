<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Thrown when outbound encryption cannot complete: a part that cannot be located, a key-wrap failure, a DOM
 * manipulation failure, or a missing wsse:Security header to attach the xenc:EncryptedKey to. Unlike
 * DecryptionFailed this is a non-oracle path, so the real reason may surface in operator logs.
 */
final class EncryptionFailed extends RuntimeException
{
    public static function withReason(string $reason): self
    {
        return new self($reason);
    }
}
