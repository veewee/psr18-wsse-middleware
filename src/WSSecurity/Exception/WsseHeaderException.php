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

    public static function ambiguousSecurityHeader(): self
    {
        return new self('The message carries more than one wsse:Security header for the ultimate receiver.');
    }

    public static function derivingTokenNotReferenceable(): self
    {
        return new self('The key a derived key derives from is not referenced by a security token reference.');
    }

    public static function nothingToSign(): self
    {
        return new self('The configured signature parts matched no element to sign.');
    }

    public static function invalidSoapVersion(string $foundNamespace): self
    {
        return new self('Unsupported SOAP envelope namespace "'.$foundNamespace.'"; expected SOAP 1.1 or 1.2.');
    }


    public static function binaryTokenNotLocatable(): self
    {
        return new self('Unable to locate the embedded wsse:BinarySecurityToken in the Security header.');
    }

    public static function samlAssertionNotParseable(string $reason): self
    {
        return new self('Unable to parse the SAML assertion XML: '.$reason.'.');
    }

    public static function samlAssertionNotLocatable(): self
    {
        return new self('The SAML assertion root element was not found in the expected SAML namespace.');
    }

    public static function samlAssertionIdMissing(string $attributeName): self
    {
        return new self('The SAML assertion is missing a non-empty "'.$attributeName.'" id attribute.');
    }
}
