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
    public static function withoutAnchors(): self
    {
        return new self(
            'A trust store needs at least one trust anchor, and the supplied PEM bundle carries no certificate.',
        );
    }

    /**
     * A trust store holds public certificates only. Key material in a file destined for one means the wrong
     * file was exported, so it is refused rather than silently ignored, and the message names the class that
     * does take a combined file: a caller here has usually reached for the wrong one of the two.
     */
    public static function withPrivateKey(): self
    {
        return new self(
            'A trust store holds public certificates only, and this PEM data also carries private key '
            .'material. Use ClientCertificate for a certificate and its private key in one file, or Key for a '
            .'private key on its own.',
        );
    }

    public static function withoutRevocationLists(): self
    {
        return new self(
            'Revocation checking requires at least one certificate revocation list: a store that requires '
            .'revocation but carries nothing to check against rejects every signer.',
        );
    }
}
