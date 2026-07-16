<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\XmlIdMinter;
use VeeWee\Xml\Dom\Document;

final class XmlIdMinterTest extends TestCase
{
    private const XML_NS = 'http://www.w3.org/XML/1998/namespace';

    private function document(): Document
    {
        return Document::fromXmlString('<root xmlns="urn:example"><a/><b/></root>');
    }

    private function element(Document $document, string $localName): Element
    {
        $element = $document->toUnsafeDocument()->getElementsByTagName($localName)->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }

    public function test_it_is_an_id_minter(): void
    {
        static::assertInstanceOf(IdMinter::class, new XmlIdMinter());
    }

    public function test_it_mints_and_stamps_an_xml_id_attribute(): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');

        $id = (new XmlIdMinter())->mint($a, $document);

        static::assertNotSame('', $id);
        static::assertSame($id, $a->getAttributeNS(self::XML_NS, 'id'));
    }

    public function test_minted_ids_are_unique_within_a_document(): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');
        $b = $this->element($document, 'b');

        $minter = new XmlIdMinter();

        static::assertNotSame($minter->mint($a, $document), $minter->mint($b, $document));
    }

    public function test_the_minted_id_is_a_valid_xml_ncname(): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');

        $id = (new XmlIdMinter())->mint($a, $document);

        static::assertMatchesRegularExpression('/^[A-Za-z_][A-Za-z0-9_.\-]*$/', $id);
        static::assertStringNotContainsString('#', $id);
    }

    public function test_mint_is_idempotent_and_returns_the_same_id_on_a_second_call(): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');
        $minter = new XmlIdMinter();

        $first = $minter->mint($a, $document);
        $second = $minter->mint($a, $document);

        static::assertSame($first, $second);
    }

    public function test_mint_reuses_an_id_the_element_already_carries(): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');
        $a->setAttributeNS(self::XML_NS, 'xml:id', 'pre-existing');

        static::assertSame('pre-existing', (new XmlIdMinter())->mint($a, $document));
    }
}
