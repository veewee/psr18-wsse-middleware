<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use RuntimeException;

/**
 * Thrown when the signing step cannot complete: an asymmetric signing failure, or a missing wsse:Security
 * header to attach the signature to. Distinct from CanonicalizationFailed so callers can tell a crypto failure
 * apart from a C14N failure.
 */
final class SigningFailed extends RuntimeException
{
    public static function cryptoError(string $reason): self
    {
        return new self('Unable to sign the document.'.($reason === '' ? '' : ' ('.$reason.')'));
    }

    public static function missingSecurityHeader(): self
    {
        return new self('No wsse:Security header was found to attach the signature to.');
    }
}
