<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Exception;

use RuntimeException;

/**
 * A trust store configured in a way that could never accept anything. Raised while building the store rather
 * than while verifying a message, so a mistake in the wiring surfaces at startup instead of as a rejected
 * response.
 */
final class InvalidTrustStore extends RuntimeException
{
    public static function withoutRevocationLists(): self
    {
        return new self(
            'Revocation checking requires at least one certificate revocation list: a store that requires '
            .'revocation but carries nothing to check against rejects every signer.',
        );
    }
}
