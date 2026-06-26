<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Exception;

use RuntimeException;

/**
 * A uniform, opaque crypto failure. Decrypt and unwrap collapse every cause (bad key, bad padding, tampered
 * data, openssl error) to one message so the engine cannot become a padding/validation oracle for a peer.
 */
final class CryptoOperationFailed extends RuntimeException
{
    public static function decryptionFailed(): self
    {
        return new self('Unable to decrypt the provided data.');
    }

    public static function invalidAuthenticationTag(): self
    {
        return new self('The authentication tag is invalid.');
    }
}
