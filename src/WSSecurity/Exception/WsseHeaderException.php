<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;

/**
 * Raised when the wsse:Security header cannot be located, created, or stamped: a malformed/non-SOAP
 * envelope, an element that cannot carry a wsu:Id, or a SOAP version that is neither 1.1 nor 1.2.
 */
final class WsseHeaderException extends RuntimeException
{
    public static function headerNotLocatable(): self
    {
        return new self('Unable to locate or create the SOAP header for the wsse:Security element.');
    }

    public static function invalidSoapVersion(string $foundNamespace): self
    {
        return new self('Unsupported SOAP envelope namespace "'.$foundNamespace.'"; expected SOAP 1.1 or 1.2.');
    }

    public static function idStampFailed(string $reason): self
    {
        return new self('Unable to stamp a wsu:Id onto the element: '.$reason.'.');
    }
}
