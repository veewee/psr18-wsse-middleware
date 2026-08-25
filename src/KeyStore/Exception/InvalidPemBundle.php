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
     * Armor inside armor is not a nesting the format has: the inner block's opening means the outer one's
     * close is missing, so the outer block's content belongs to something else. It is refused rather than
     * read whole, which is what would fold a private key into a certificate, or a certificate into a key.
     */
    public static function nestedArmor(): self
    {
        return new self('A block in the PEM data has another PEM block nested inside it.');
    }

    /**
     * The same argument as a truncated certificate: a key block that is not properly closed is refused rather
     * than skipped, so a half-transferred file cannot load as an identity quietly missing its key. Covers both
     * an opening with no close at all and a pair whose labels disagree, hence the wording.
     */
    public static function truncatedPrivateKey(): self
    {
        return new self('A private key block in the PEM data is not properly closed, so the data is truncated.');
    }

    /**
     * With two keys in the file nothing states which identity is yours, and taking the first would let the
     * file's layout decide what a message gets signed with.
     */
    public static function withMultiplePrivateKeys(): self
    {
        return new self('The PEM data carries more than one private key, so which identity it holds is undecided.');
    }
}
