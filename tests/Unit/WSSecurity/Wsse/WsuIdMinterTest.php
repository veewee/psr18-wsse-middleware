<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Wsse;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdResolver;
use VeeWee\Xml\Dom\Document;

final class WsuIdMinterTest extends TestCase
{
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    private function bodyElement(Document $document): Element
    {
        $element = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP12, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }

    private function document(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header/><soap:Body><a/><b/></soap:Body></soap:Envelope>'
        );
    }

    public function test_it_mints_and_stamps_a_wsu_id_attribute(): void
    {
        $document = $this->document();
        $body = $this->bodyElement($document);

        $id = (new WsuIdMinter())->mint($body, $document);

        static::assertSame($id, $body->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_the_minted_id_resolves_to_the_exact_element(): void
    {
        $document = $this->document();
        $body = $this->bodyElement($document);

        $id = (new WsuIdMinter())->mint($body, $document);

        static::assertSame($body, WsuIdResolver::resolve($document, $id));
    }

    public function test_minted_ids_are_unique_within_a_document(): void
    {
        $document = $this->document();
        $unsafe = $document->toUnsafeDocument();
        $a = $unsafe->getElementsByTagName('a')->item(0);
        $b = $unsafe->getElementsByTagName('b')->item(0);
        static::assertInstanceOf(Element::class, $a);
        static::assertInstanceOf(Element::class, $b);

        $minter = new WsuIdMinter();

        static::assertNotSame($minter->mint($a, $document), $minter->mint($b, $document));
    }

    public function test_the_minted_id_is_a_valid_xml_ncname(): void
    {
        $document = $this->document();
        $body = $this->bodyElement($document);

        $id = (new WsuIdMinter())->mint($body, $document);

        static::assertMatchesRegularExpression('/^[A-Za-z_][A-Za-z0-9_.\-]*$/', $id);
        static::assertStringNotContainsString('#', $id);
    }
}
