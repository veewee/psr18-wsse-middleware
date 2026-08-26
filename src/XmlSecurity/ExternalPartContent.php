<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Throwable;
use VeeWee\Xml\Dom\Document;

use function VeeWee\Xml\Dom\Configurator\disallow_doctype;

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
 */
final readonly class ExternalPartContent
{
    public function __construct(
        private Canonicalizer $canonicalizer,
    ) {
    }

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
     * XML content is canonicalized as a whole document with exclusive C14N and no prefix list, comments
     * omitted. The document node rather than the root element: a peer digests the whole node-set, so a
     * processing instruction sitting outside the root is part of what was signed.
     *
     * Text content is normalized so that a CR, an LF and a CRLF all become a CRLF, which is what lets a part
     * survive an intermediary that rewrites line endings, something MIME permits for text and not for binary.
     * A lone CR is a line ending in its own right, so an LF following anything other than a CR is a second
     * one rather than the tail of the first.
     *
     * Anything else is returned untouched, because a peer digests it untouched.
     *
     * @throws CanonicalizationFailed when XML content cannot be read as a document
     */
    public function canonicalize(string $mimeType, string $octets): string
    {
        if (self::isXml($mimeType)) {
            return $this->canonicalizer->canonicalize($this->parse($octets), SignatureCanonicalization::EXC_C14N);
        }

        if (!str_starts_with(strtolower($mimeType), 'text/')) {
            return $octets;
        }

        return (string) preg_replace('/\r\n|\r|\n/', "\r\n", $octets);
    }

    /**
     * Reads the part as a document with the same doctype refusal the rest of this package applies to bytes a
     * peer chose. A peer refuses one here too, so this is not a divergence: a part carrying a doctype is
     * signable by neither side.
     *
     * @throws CanonicalizationFailed
     */
    private function parse(string $octets): \Dom\Document
    {
        if ($octets === '') {
            throw CanonicalizationFailed::unreadableExternalPart();
        }

        try {
            return Document::fromXmlString($octets, disallow_doctype())->toUnsafeDocument();
        } catch (Throwable $exception) {
            throw CanonicalizationFailed::unreadableExternalPart($exception);
        }
    }
}
