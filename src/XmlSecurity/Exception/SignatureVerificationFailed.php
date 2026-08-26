<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use RuntimeException;
use Throwable;

/**
 * Signature verification was refused. The single named constructor takes an operator-log reason but the type
 * is uniform: every verification failure, whatever its cause, surfaces as this one exception so a caller can
 * never tell which check failed and the exception cannot be used as a forgery oracle.
 *
 * The inbound layer is expected to collapse this into one uniform fault before anything reaches a remote peer.
 */
final class SignatureVerificationFailed extends RuntimeException
{
    /**
     * The cause, when there is one, is chained for the operator log only. It never reaches a peer: the inbound
     * layer collapses this whole type into one fault whose message says nothing about which check failed.
     */
    public static function withReason(string $reason, ?Throwable $previous = null): self
    {
        return new self($reason, 0, $previous);
    }
}
