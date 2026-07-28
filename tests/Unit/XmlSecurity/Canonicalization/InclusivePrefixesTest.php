<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Canonicalization;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\InclusivePrefixes;
use VeeWee\Xml\Dom\Document;

/**
 * The two expectations for a WSSE envelope are taken from the committed WSS4J output in
 * tests/fixtures/interop/wss4j-signed.xml, which declares PrefixList="wsse soap" on the Timestamp
 * reference, no PrefixList at all on the Body reference, and PrefixList="soap" on the SignedInfo
 * canonicalization method.
 */
final class InclusivePrefixesTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_a_signed_element_pins_the_ancestor_prefixes_it_does_not_itself_use(): void
    {
        $timestamp = $this->locate($this->envelope(), self::WSU, 'Timestamp');

        static::assertSame(['wsse', 'soap'], InclusivePrefixes::forSignedElement($timestamp));
    }

    public function test_a_signed_element_pins_nothing_when_it_uses_every_prefix_it_inherits(): void
    {
        $body = $this->locate($this->envelope(), self::SOAP, 'Body');

        static::assertSame([], InclusivePrefixes::forSignedElement($body));
    }

    public function test_a_prefix_used_only_by_an_attribute_of_the_signed_element_is_not_pinned(): void
    {
        $document = Document::fromXmlString(
            '<a:root xmlns:a="urn:a" xmlns:b="urn:b"><a:child b:flag="1"/></a:root>',
        );

        static::assertSame([], InclusivePrefixes::forSignedElement($this->locate($document, 'urn:a', 'child')));
    }

    public function test_an_inherited_default_namespace_is_pinned_as_hash_default(): void
    {
        $document = Document::fromXmlString('<root xmlns="urn:def" xmlns:a="urn:a"><a:child/></root>');

        static::assertSame(['#default'], InclusivePrefixes::forSignedElement($this->locate($document, 'urn:a', 'child')));
    }

    public function test_a_prefix_declared_at_two_levels_is_pinned_once(): void
    {
        $document = Document::fromXmlString(
            '<a:root xmlns:a="urn:a" xmlns:b="urn:b"><a:mid xmlns:b="urn:b"><a:child/></a:mid></a:root>',
        );

        static::assertSame(['b'], InclusivePrefixes::forSignedElement($this->locate($document, 'urn:a', 'child')));
    }

    public function test_a_container_pins_every_prefix_in_scope_from_outside_it(): void
    {
        $security = $this->locate($this->envelope(), self::WSSE, 'Security');

        // The container keeps its own prefix: the SignedInfo being canonicalized is a descendant, not the
        // container itself, so nothing about the container's tag makes wsse visibly utilized there.
        static::assertSame(['soap'], InclusivePrefixes::forContainer($security));
    }

    public function test_an_element_with_no_ancestors_pins_nothing(): void
    {
        $document = Document::fromXmlString('<a:root xmlns:a="urn:a"><a:child/></a:root>');
        $root = $this->locate($document, 'urn:a', 'root');

        static::assertSame([], InclusivePrefixes::forSignedElement($root));
        static::assertSame([], InclusivePrefixes::forContainer($root));
    }

    public function test_a_prefix_only_a_serialization_would_declare_is_pinned(): void
    {
        // An ancestor built in memory carries no xmlns attribute until the document is serialized, so deriving
        // from the live tree must still count the binding the wire will declare.
        $document = Document::fromXmlString('<root xmlns:a="urn:a"><a:mid/></root>');
        $native = $document->toUnsafeDocument();
        $mid = $this->locate($document, 'urn:a', 'mid');
        $wrapper = $native->createElementNS('urn:brandnew', 'nv:wrapper');
        $mid->appendChild($wrapper);
        $container = $native->createElementNS('urn:c', 'c:container');
        $wrapper->appendChild($container);

        static::assertSame(['nv', 'a'], InclusivePrefixes::forContainer($container));

        // The same list the wire yields, which is the whole point of counting the binding.
        $wire = Document::fromXmlString($document->toXmlString());
        static::assertSame(
            InclusivePrefixes::forContainer($container),
            InclusivePrefixes::forContainer($this->locate($wire, 'urn:c', 'container')),
        );
    }

    private function envelope(): Document
    {
        return Document::fromXmlString(sprintf(
            '<soap:Envelope xmlns:soap="%s">'
            .'<soap:Header><wsse:Security xmlns:wsse="%s" xmlns:wsu="%s" soap:mustUnderstand="true">'
            .'<wsu:Timestamp wsu:Id="TS-1"/>'
            .'</wsse:Security></soap:Header>'
            .'<soap:Body xmlns:wsu="%s" wsu:Id="id-1"/>'
            .'</soap:Envelope>',
            self::SOAP,
            self::WSSE,
            self::WSU,
            self::WSU,
        ));
    }

    private function locate(Document $document, string $namespace, string $localName): Element
    {
        $element = $document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName)->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }
}
