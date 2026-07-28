<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use Dom\Element;
use LogicException;
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
 * After __invoke, assertionId() returns the assertion's id (AssertionID for 1.1, ID for 2.0) so a caller can
 * wire a SamlAssertionKeyIdentifier into an Outbound\Signature block for the Holder-of-Key path. The block
 * never mints a fresh wsu:Id; re-minting would break a pre-existing signature over the assertion's id.
 */
final class SamlAssertion implements OutboundAction
{
    /** @var non-empty-string|null */
    private ?string $assertionId = null;

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
        $assertionId = $this->extractId($assertion);

        $header = SecurityHeader::forContext($context);
        $header->appendChildren(
            static fn (Element $security): Element => assert_element(append_external_node($security, $assertion)),
        );

        $this->assertionId = $assertionId;
    }

    /**
     * @return non-empty-string the assertion id, without a '#' prefix
     *
     * @throws LogicException when called before __invoke
     */
    public function assertionId(): string
    {
        if ($this->assertionId === null) {
            throw new LogicException('SAML assertion not yet imported; call __invoke first.');
        }

        return $this->assertionId;
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
