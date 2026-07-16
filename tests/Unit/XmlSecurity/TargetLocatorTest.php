<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

final class TargetLocatorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const XML = 'http://www.w3.org/XML/1998/namespace';

    public function test_it_locates_an_element_by_namespaced_tag_name(): void
    {
        $element = (new TargetLocator())->locate($this->document(), Target::element('urn:custom', 'Payload'));

        static::assertSame('Payload', $element->localName);
        static::assertSame('urn:custom', $element->namespaceURI);
    }

    public function test_it_locates_the_soap_body_by_qualified_name(): void
    {
        $element = (new TargetLocator())->locate($this->document(), Target::element(self::SOAP, 'Body'));

        static::assertSame('Body', $element->localName);
        static::assertSame(self::SOAP, $element->namespaceURI);
    }

    public function test_it_locates_an_element_by_id_using_the_engine_default_convention(): void
    {
        $element = (new TargetLocator())->locate($this->document(), Target::byId('Body-1'));

        static::assertSame('Body', $element->localName);
    }

    public function test_it_throws_when_an_element_is_absent(): void
    {
        $document = Document::fromXmlString('<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body/></soap:Envelope>');

        $this->expectException(IdReferenceException::class);
        (new TargetLocator())->locate($document, Target::element(self::WSU, 'Timestamp'));
    }

    public function test_it_throws_when_an_id_is_ambiguous(): void
    {
        // libxml rejects a duplicate xml:id at parse time, so the duplicate is injected onto the live DOM.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body><a/><b/></soap:Body></soap:Envelope>'
        );
        $unsafe = $document->toUnsafeDocument();
        foreach (['a', 'b'] as $name) {
            $unsafe->getElementsByTagName($name)->item(0)?->setAttributeNS(self::XML, 'xml:id', 'dup');
        }

        $this->expectException(IdReferenceException::class);
        (new TargetLocator())->locate($document, Target::byId('dup'));
    }

    private function document(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security><wsu:Timestamp/></wsse:Security></soap:Header>'
            .'<soap:Body xml:id="Body-1"><p:Payload xmlns:p="urn:custom"/></soap:Body>'
            .'</soap:Envelope>'
        );
    }
}
