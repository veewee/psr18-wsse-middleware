<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Exception;

use RuntimeException;

/**
 * An openssl_* call reported failure. Carries the real, human-readable reason captured from the OpenSSL
 * error queue and any boxed PHP warning. Safe to surface on non-oracle paths (signing, encryption, key
 * wrapping, certificate parsing); the decrypt / unwrap / verify paths catch it and collapse to a uniform
 * result so it cannot become a padding/validation oracle.
 */
final class OpenSslException extends RuntimeException
{
    public static function operationFailed(string $operation, string $reason): self
    {
        $message = 'Unable to '.$operation.'.';

        return new self($reason === '' ? $message : $message.' ('.$reason.')');
    }
}
