<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Wsse;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\SecurityTokenReference;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

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

    public function test_embedded_variant_wraps_the_child_element(): void
    {
        $childBuilder = namespaced_element(self::WSSE, 'wsse:Assertion', value('inline'));

        $str = SecurityTokenReference::embedded($childBuilder)->build($this->document());

        $embedded = $this->firstChildElement($str);
        static::assertSame('Embedded', $embedded->localName);
        static::assertSame(self::WSSE, $embedded->namespaceURI);

        $assertion = $this->firstChildElement($embedded);
        static::assertSame('Assertion', $assertion->localName);
        static::assertSame('inline', $assertion->textContent);
    }

    public function test_key_name_variant_emits_a_ds_key_name(): void
    {
        $str = SecurityTokenReference::keyName('CN=Service')->build($this->document());

        $keyName = $this->firstChildElement($str);
        static::assertSame('KeyName', $keyName->localName);
        static::assertSame(self::DS, $keyName->namespaceURI);
        static::assertSame('CN=Service', $keyName->textContent);
    }
}
