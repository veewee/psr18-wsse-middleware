<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;
use Throwable;

/**
 * The single inbound failure type. Every inbound block maps its internal exception (decryption, signature
 * verification, timestamp expiry, structural parse error) to this one type before throwing. A caller
 * receiving a SecurityFault cannot tell which block failed, which step within it failed, or any detail
 * about the message content that triggered the failure: the message is always identical. This is the
 * no-oracle guarantee for the inbound path.
 *
 * The specific cause is chained as the previous exception for operator logging only; it must never reach a
 * remote peer or a caller-observable SOAP fault detail.
 */
final class SecurityFault extends RuntimeException
{
    public static function inboundFailure(?Throwable $previous = null): self
    {
        return new self('The inbound security header could not be processed.', 0, $previous);
    }
}
