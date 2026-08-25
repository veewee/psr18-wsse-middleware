<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use RuntimeException;

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
     * An XML external part. The SwA content transform canonicalizes XML content with exclusive C14N before
     * digesting, which this cut does not implement, so the media type is refused rather than digested in a
     * form no peer computes.
     */
    public static function xmlExternalPart(string $reference, string $mimeType): self
    {
        return new self(sprintf(
            'Unable to sign the external part "%s": signing a %s part needs XML canonicalization, which is '
            .'not supported.',
            $reference,
            $mimeType,
        ));
    }

    /**
     * A text external part. The SwA content transform normalizes line endings in text content before
     * digesting, which this cut does not implement, so the media type is refused rather than digested under a
     * rule we would be guessing at.
     */
    public static function textExternalPart(string $reference, string $mimeType): self
    {
        return new self(sprintf(
            'Unable to sign the external part "%s": signing a %s part needs content line-ending '
            .'canonicalization, which is not supported.',
            $reference,
            $mimeType,
        ));
    }
}
