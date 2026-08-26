<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

/**
 * How an external part's content is converted to the octets a signature digests.
 *
 * The content transform is not the identity for every part. It branches on the media type three ways: XML is
 * canonicalized with exclusive C14N, any other text is normalized to CRLF line endings, and everything else
 * is digested exactly as it travels. A peer applies the same branch before digesting, so getting it wrong
 * produces a signature only this package can verify.
 *
 * The branch lives here rather than at each call site because signing and verifying have to make the same
 * choice for the same part. Two copies of a three-way rule is one copy too many: the digest they produce has
 * to be identical or nothing verifies.
 *
 * XML is not converted here. Deciding what to do about it belongs to the caller, which knows whether it is
 * refusing to sign or refusing to verify and owns the exception that says so.
 */
final class ExternalPartContent
{
    /**
     * XML content as the peers reckon it: text/xml, application/xml, and the "+xml" structured-syntax suffix
     * under application and image alone. Each may carry media-type parameters.
     */
    public static function isXml(string $mimeType): bool
    {
        return (bool) preg_match(
            '#^(text/xml|application/xml|(application|image)/[^;]*\+xml)(;|$)#',
            strtolower($mimeType),
        );
    }

    /**
     * The octets to digest for a part of this media type.
     *
     * Text content is normalized so that a CR, an LF and a CRLF all become a CRLF, which is what lets a part
     * survive an intermediary that rewrites line endings, something MIME permits for text and not for binary.
     * A lone CR is a line ending in its own right, so an LF following anything other than a CR is a second
     * one rather than the tail of the first.
     *
     * Anything not text is returned untouched, XML included: the caller decides what happens to that.
     */
    public static function canonicalize(string $mimeType, string $octets): string
    {
        if (self::isXml($mimeType) || !str_starts_with(strtolower($mimeType), 'text/')) {
            return $octets;
        }

        return (string) preg_replace('/\r\n|\r|\n/', "\r\n", $octets);
    }
}
