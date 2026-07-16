<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Exception;

use RuntimeException;

/**
 * Raised when certificate bytes cannot be decoded into a usable PEM/DER form. A key-material concern that
 * belongs to the key store, independent of how any protocol layer later carries the certificate.
 */
final class InvalidCertificate extends RuntimeException
{
    public static function malformedEncoding(string $reason): self
    {
        return new self('Unable to decode the certificate: '.$reason.'.');
    }
}
