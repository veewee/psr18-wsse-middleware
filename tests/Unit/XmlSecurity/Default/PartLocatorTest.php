<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Default;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\PartLocator;
use VeeWee\Xml\Dom\Document;

final class PartLocatorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_it_locates_the_soap_body(): void
    {
        $element = (new PartLocator())->locate($this->document(), Part::body());

        static::assertSame('Body', $element->localName);
        static::assertSame(self::SOAP, $element->namespaceURI);
    }

    public function test_it_locates_the_timestamp(): void
    {
        $element = (new PartLocator())->locate($this->document(), Part::timestamp());

        static::assertSame('Timestamp', $element->localName);
        static::assertSame(self::WSU, $element->namespaceURI);
    }

    public function test_it_locates_an_element_by_namespaced_tag_name(): void
    {
        $element = (new PartLocator())->locate($this->document(), Part::element('urn:custom', 'Payload'));

        static::assertSame('Payload', $element->localName);
        static::assertSame('urn:custom', $element->namespaceURI);
    }

    public function test_it_locates_an_element_by_wsu_id(): void
    {
        $element = (new PartLocator())->locate($this->document(), Part::byId('Body-1'));

        static::assertSame('Body', $element->localName);
    }

    public function test_it_throws_when_a_part_is_absent(): void
    {
        $document = Document::fromXmlString('<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body/></soap:Envelope>');

        $this->expectException(IdReferenceException::class);
        (new PartLocator())->locate($document, Part::timestamp());
    }

    public function test_it_throws_when_an_id_is_ambiguous(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Body><a wsu:Id="dup"/><b wsu:Id="dup"/></soap:Body></soap:Envelope>'
        );

        $this->expectException(IdReferenceException::class);
        (new PartLocator())->locate($document, Part::byId('dup'));
    }

    private function document(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security><wsu:Timestamp/></wsse:Security></soap:Header>'
            .'<soap:Body wsu:Id="Body-1"><p:Payload xmlns:p="urn:custom"/></soap:Body>'
            .'</soap:Envelope>'
        );
    }
}
