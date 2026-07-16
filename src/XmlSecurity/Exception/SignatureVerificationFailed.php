<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use RuntimeException;

/**
 * Signature verification was refused. The single named constructor takes an operator-log reason but the type
 * is uniform: every verification failure, whatever its cause, surfaces as this one exception so a caller can
 * never tell which check failed and the exception cannot be used as a forgery oracle.
 *
 * The inbound layer is expected to collapse this into one uniform fault before anything reaches a remote peer.
 */
final class SignatureVerificationFailed extends RuntimeException
{
    public static function withReason(string $reason): self
    {
        return new self($reason);
    }
}
