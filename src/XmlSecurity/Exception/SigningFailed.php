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
