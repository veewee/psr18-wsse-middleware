<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use RuntimeException;

/**
 * Decryption was refused. The single named constructor takes an operator-log reason but the type is uniform:
 * every inbound decryption failure, whatever its cause (OAEP refusal, key-unwrap failure, cipher failure,
 * structural parse error, part-count cap), surfaces as this one exception so a caller can never tell which
 * step failed and the exception cannot be used as a padding or validation oracle.
 *
 * The inbound layer is expected to collapse this into one uniform fault before anything reaches a remote peer.
 */
final class DecryptionFailed extends RuntimeException
{
    public static function withReason(string $reason): self
    {
        return new self($reason);
    }
}
