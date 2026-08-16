<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Assert\assert_element;
use function VeeWee\Xml\Dom\Configurator\disallow_doctype;
use function VeeWee\Xml\Dom\Locator\document_element;
use function VeeWee\Xml\Dom\Manipulator\Node\append_external_node;

/**
 * Imports a caller-supplied SAML 1.1 or 2.0 assertion into the outbound wsse:Security header. The assertion
 * XML is parsed into an isolated document with DOCTYPE declarations rejected, so a malicious assertion string
 * cannot inject content through entity expansion or external references; only parsed nodes are adopted into the
 * envelope, never raw bytes. The assertion is imported verbatim, including any signature it already carries.
 *
 * The block keeps no per-message state, so it is safe to reuse across messages and under a worker that holds
 * one middleware for the lifetime of the process. A Holder-of-Key signature needs the assertion's id, and it
 * reads that off the assertion in the header rather than being handed it here: Outbound\Signature with
 * KeyRef::SamlAssertion finds what this block left behind, the same way the direct-reference path finds the
 * binary token it embedded.
 *
 * The id the assertion arrived with is never re-minted: a fresh one would break the issuer's signature over it.
 */
final class SamlAssertion implements OutboundAction
{
    /**
     * @param non-empty-string $assertionXml the full saml:Assertion element as a well-formed XML string
     */
    public function __construct(
        private readonly string $assertionXml,
        private readonly SamlVersion $version,
    ) {
    }

    public function __invoke(WsseContext $context): void
    {
        $assertion = $this->parseAssertion();
        // Read for its side effect: an assertion with no usable id is refused here rather than after it has
        // been written into the header, where a signature would later fail to reference it.
        $this->extractId($assertion);

        $header = SecurityHeader::forContext($context);
        $header->appendChildren(
            static fn (Element $security): Element => assert_element(append_external_node($security, $assertion)),
        );
    }

    /**
     * @throws WsseHeaderException when the assertion XML is not parseable or its root is not the expected
     *                             SAML assertion element
     */
    private function parseAssertion(): Element
    {
        try {
            $document = Document::fromXmlString($this->assertionXml, disallow_doctype());
            $root = $document->locate(document_element());
        } catch (Throwable $exception) {
            throw WsseHeaderException::samlAssertionNotParseable($exception->getMessage());
        }

        if (!ElementName::matchesUri($root, $this->version->value, 'Assertion')) {
            throw WsseHeaderException::samlAssertionNotLocatable();
        }

        return $root;
    }

    /**
     * @return non-empty-string
     *
     * @throws WsseHeaderException when the version-specific id attribute is absent or empty
     */
    private function extractId(Element $assertion): string
    {
        $attribute = $this->version->idAttribute();
        $id = $assertion->getAttribute($attribute);

        if ($id === null || $id === '') {
            throw WsseHeaderException::samlAssertionIdMissing($attribute);
        }

        return $id;
    }
}
