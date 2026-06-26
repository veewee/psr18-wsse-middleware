<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Wsse;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\NodeOrder;
use VeeWee\Xml\Dom\Document;

final class NodeOrderTest extends TestCase
{
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    private function security(string $innerXml): Element
    {
        $document = Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.self::SOAP12.'"'
            .' xmlns:wsse="'.self::WSSE.'"'
            .' xmlns:wsu="'.self::WSU.'"'
            .' xmlns:ds="'.self::DS.'"'
            .' xmlns:xenc="'.self::XENC.'">'
            .'<soap:Header><wsse:Security>'.$innerXml.'</wsse:Security></soap:Header>'
            .'<soap:Body/></soap:Envelope>'
        );

        $element = $document->toUnsafeDocument()->getElementsByTagNameNS(self::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }

    /** @return list<string> */
    private function childLocalNames(Element $element): array
    {
        $names = [];
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element) {
                $names[] = $child->localName;
            }
        }

        return $names;
    }

    public function test_it_sorts_children_into_the_canonical_order(): void
    {
        $security = $this->security(
            '<xenc:EncryptedData/>'
            .'<ds:Signature/>'
            .'<xenc:ReferenceList/>'
            .'<xenc:EncryptedKey/>'
            .'<wsu:Timestamp/>'
            .'<wsse:BinarySecurityToken/>'
        );

        NodeOrder::sort($security);

        static::assertSame(
            ['BinarySecurityToken', 'Timestamp', 'EncryptedKey', 'ReferenceList', 'Signature', 'EncryptedData'],
            $this->childLocalNames($security),
        );
    }

    public function test_sign_then_encrypt_places_encrypted_key_before_signature(): void
    {
        $security = $this->security('<ds:Signature/><xenc:EncryptedKey/>');

        NodeOrder::sort($security);

        static::assertSame(['EncryptedKey', 'Signature'], $this->childLocalNames($security));
    }

    public function test_sorting_is_idempotent(): void
    {
        $security = $this->security(
            '<ds:Signature/><xenc:EncryptedKey/><wsu:Timestamp/>'
        );

        NodeOrder::sort($security);
        $once = $this->childLocalNames($security);
        NodeOrder::sort($security);
        $twice = $this->childLocalNames($security);

        static::assertSame($once, $twice);
    }

    public function test_it_leaves_unknown_children_after_the_known_ones_in_order(): void
    {
        $security = $this->security(
            '<wsse:Custom1/><ds:Signature/><wsse:Custom2/><wsu:Timestamp/>'
        );

        NodeOrder::sort($security);

        static::assertSame(
            ['Timestamp', 'Signature', 'Custom1', 'Custom2'],
            $this->childLocalNames($security),
        );
    }

    public function test_sorting_an_empty_element_is_a_noop(): void
    {
        $security = $this->security('');

        NodeOrder::sort($security);

        static::assertSame([], $this->childLocalNames($security));
    }
}
