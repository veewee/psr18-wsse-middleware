<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use RuntimeException;
use Throwable;

/**
 * Thrown when the signing step cannot complete because of an asymmetric signing failure. Distinct from
 * CanonicalizationFailed so callers can tell a crypto failure apart from a C14N failure.
 */
final class SigningFailed extends RuntimeException
{
    public static function cryptoError(string $reason): self
    {
        return new self('Unable to sign the document.'.($reason === '' ? '' : ' ('.$reason.')'));
    }

    /**
     * A part the caller registered that the signature does not name.
     *
     * The signer reports what it covered rather than the block assuming it did as asked, so a replaceable
     * seam cannot quietly return a signature over less than it was handed and leave the caller sending an
     * attachment they configured as signed.
     */
    public static function uncoveredExternalPart(string $reference): self
    {
        return new self(sprintf(
            'The signature does not cover the external part "%s", which was registered.',
            $reference,
        ));
    }

    /**
     * An element whose content is a pointer at bytes this signature does not cover.
     *
     * Signing it would protect the reference while the file it names travels in its own MIME part, and the
     * message would still satisfy a policy check for that element being signed. Naming the reference, because
     * outbound this is the caller's own message and nothing about it is a secret from them.
     */
    public static function uncoveredOptimizedContent(string $reference): self
    {
        return new self(sprintf(
            'A signed element points at content the signature does not cover: "%s". Register the attachment '
            .'it names so the bytes are signed too, rather than only the reference to them.',
            $reference,
        ));
    }

    /**
     * A part whose stream reads nothing.
     *
     * Signing nothing produces a signature that verifies, so the caller ships an empty file believing it was
     * protected and nothing downstream notices. A part whose stream cannot rewind reads this way too. The
     * encryption side refuses the same part for the same reason.
     */
    public static function emptyExternalPart(string $reference): self
    {
        return new self(sprintf('The external part "%s" read zero bytes.', $reference));
    }

    /**
     * A part declaring an XML media type whose octets are not a document.
     *
     * The transform canonicalizes XML content before digesting, so there has to be a node-set to canonicalize.
     * Naming the part and its media type, because outbound this is the caller's own attachment and nothing
     * about their own message is a secret from them.
     */
    public static function unreadableExternalPart(string $reference, string $mimeType, ?Throwable $previous = null): self
    {
        return new self(
            sprintf(
                'Unable to sign the external part "%s": its %s content could not be read as a document.',
                $reference,
                $mimeType,
            ),
            0,
            $previous,
        );
    }
}
