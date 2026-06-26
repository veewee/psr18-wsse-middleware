<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;

/**
 * Thrown when the signing step cannot complete: an asymmetric signing failure, an algorithm that the signer
 * cannot perform, or a missing wsse:Security header to attach the signature to. Distinct from
 * CanonicalizationFailed so callers can tell a crypto failure apart from a C14N failure.
 */
final class SigningFailed extends RuntimeException
{
    public static function cryptoError(string $reason): self
    {
        return new self('Unable to sign the document.'.($reason === '' ? '' : ' ('.$reason.')'));
    }

    public static function unsupportedAlgorithm(SignatureMethod $method): self
    {
        return new self('The signature method "'.$method->value.'" cannot be used for signing here.');
    }

    public static function missingSecurityHeader(): self
    {
        return new self('No wsse:Security header was found to attach the signature to.');
    }
}
