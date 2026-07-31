<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Exception;

use RuntimeException;

/**
 * PEM data that cannot serve as a certificate bundle. Raised while reading the bundle rather than while
 * verifying a message, so a wrong or truncated file surfaces at startup instead of as a rejected response.
 */
final class InvalidPemBundle extends RuntimeException
{
    public static function withoutCertificate(): self
    {
        return new self('The PEM data does not contain a PEM certificate block.');
    }

    /**
     * A certificate that opens and never closes is refused rather than skipped. Skipping it would load the
     * certificates that did survive and call that the trust store, quietly dropping an anchor.
     */
    public static function truncatedCertificate(): self
    {
        return new self('A certificate block in the PEM data is never closed, so the data is truncated.');
    }

    /**
     * A bundle holds public certificates only. Key material in a file destined for a trust store means the
     * wrong file was exported, so it is refused rather than silently ignored, and the message names the class
     * that does take a combined file: a caller here has usually reached for the wrong one of the two.
     */
    public static function containsPrivateKey(): self
    {
        return new self(
            'A PEM bundle holds public certificates only, and this data also carries private key material. '
            .'Use ClientCertificate for a certificate and its private key in one file, or Key for a private '
            .'key on its own.',
        );
    }
}
