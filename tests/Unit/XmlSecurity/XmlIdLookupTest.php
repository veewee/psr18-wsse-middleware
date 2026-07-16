<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\XmlIdLookup;
use VeeWee\Xml\Dom\Document;

final class XmlIdLookupTest extends TestCase
{
    private const XML_NS = 'http://www.w3.org/XML/1998/namespace';

    public function test_it_is_an_id_lookup(): void
    {
        static::assertInstanceOf(IdLookup::class, new XmlIdLookup());
    }

    public function test_it_resolves_the_exact_element_carrying_the_xml_id(): void
    {
        $document = Document::fromXmlString(
            '<root xmlns="urn:example"><a xml:id="target"/><b/></root>'
        );
        $expected = $document->toUnsafeDocument()->getElementsByTagName('a')->item(0);

        static::assertSame($expected, (new XmlIdLookup())->lookup($document, 'target'));
    }

    public function test_it_throws_when_no_element_carries_the_id(): void
    {
        $document = Document::fromXmlString('<root xmlns="urn:example"><a xml:id="other"/></root>');

        $this->expectException(IdReferenceException::class);

        (new XmlIdLookup())->lookup($document, 'missing');
    }

    public function test_it_rejects_a_duplicate_id_as_ambiguous(): void
    {
        // libxml rejects a duplicate xml:id at parse time, so the duplicate is injected onto the live DOM to
        // exercise the ambiguity guard the way an XML Signature Wrapping payload would present it.
        $document = Document::fromXmlString('<root xmlns="urn:example"><a/><b/></root>');
        $unsafe = $document->toUnsafeDocument();
        foreach (['a', 'b'] as $name) {
            $unsafe->getElementsByTagName($name)->item(0)?->setAttributeNS(self::XML_NS, 'xml:id', 'dup');
        }

        $this->expectException(IdReferenceException::class);

        (new XmlIdLookup())->lookup($document, 'dup');
    }
}
