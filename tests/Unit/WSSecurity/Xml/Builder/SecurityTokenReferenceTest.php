<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml\Builder;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use VeeWee\Xml\Dom\Document;

final class SecurityTokenReferenceTest extends TestCase
{
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    private function document(): Document
    {
        return Document::fromXmlString('<root/>');
    }

    private function firstChildElement(Element $element): Element
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element) {
                return $child;
            }
        }

        static::fail('No child element found.');
    }

    public function test_reference_variant_emits_a_fragment_uri(): void
    {
        $str = SecurityTokenReference::reference('id-123', 'urn:value-type')
            ->build($this->document());

        static::assertSame('SecurityTokenReference', $str->localName);
        static::assertSame(self::WSSE, $str->namespaceURI);

        $reference = $this->firstChildElement($str);
        static::assertSame('Reference', $reference->localName);
        static::assertSame(self::WSSE, $reference->namespaceURI);
        static::assertSame('#id-123', $reference->getAttribute('URI'));
        static::assertSame('urn:value-type', $reference->getAttribute('ValueType'));
    }

    public function test_key_identifier_variant_emits_value_type_encoding_and_content(): void
    {
        $str = SecurityTokenReference::keyIdentifier('ZW5jb2RlZA==', 'urn:value-type', 'urn:encoding')
            ->build($this->document());

        $keyIdentifier = $this->firstChildElement($str);
        static::assertSame('KeyIdentifier', $keyIdentifier->localName);
        static::assertSame(self::WSSE, $keyIdentifier->namespaceURI);
        static::assertSame('urn:value-type', $keyIdentifier->getAttribute('ValueType'));
        static::assertSame('urn:encoding', $keyIdentifier->getAttribute('EncodingType'));
        static::assertSame('ZW5jb2RlZA==', $keyIdentifier->textContent);
    }

    public function test_x509_issuer_serial_variant_emits_a_ds_x509_data_issuer_serial(): void
    {
        $str = SecurityTokenReference::x509IssuerSerial('CN=Issuer', '4242')->build($this->document());

        static::assertSame('SecurityTokenReference', $str->localName);
        static::assertSame(self::WSSE, $str->namespaceURI);

        $x509Data = $this->firstChildElement($str);
        static::assertSame('X509Data', $x509Data->localName);
        static::assertSame(self::DS, $x509Data->namespaceURI);

        $issuerSerial = $this->firstChildElement($x509Data);
        static::assertSame('X509IssuerSerial', $issuerSerial->localName);
        static::assertSame(self::DS, $issuerSerial->namespaceURI);

        $issuerName = $this->firstChildElement($issuerSerial);
        static::assertSame('X509IssuerName', $issuerName->localName);
        static::assertSame(self::DS, $issuerName->namespaceURI);
        static::assertSame('CN=Issuer', $issuerName->textContent);

        $serialNumber = $issuerSerial->lastElementChild;
        static::assertInstanceOf(Element::class, $serialNumber);
        static::assertSame('X509SerialNumber', $serialNumber->localName);
        static::assertSame(self::DS, $serialNumber->namespaceURI);
        static::assertSame('4242', $serialNumber->textContent);
    }
}
