<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\DynamicPartMembers;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use VeeWee\Xml\Dom\Document;

/**
 * Pins the enumeration both directions depend on: the outbound Signature block mints an id on every member it
 * returns, and the inbound RequiredPartsValidator demands every member was signed. A member wrongly dropped
 * here silently narrows what "everything in the header was signed" means.
 */
final class DynamicPartMembersTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_a_static_part_expands_to_nothing(): void
    {
        $security = $this->securityHeaderInEnvelope();

        static::assertNull(DynamicPartMembers::forPart(Part::body(), $security));
    }

    public function test_security_header_contents_lists_every_child_except_the_signature(): void
    {
        $security = $this->securityHeaderInEnvelope();

        $members = DynamicPartMembers::forPart(Part::securityHeaderContents(), $security);

        static::assertNotNull($members);
        static::assertSame(['Timestamp', 'BinarySecurityToken'], $this->localNames($members));
    }

    public function test_security_header_contents_keeps_document_order(): void
    {
        $security = $this->securityHeaderInEnvelope();
        $members = DynamicPartMembers::forPart(Part::securityHeaderContents(), $security);

        static::assertNotNull($members);
        static::assertSame(array_keys($members), range(0, count($members) - 1));
    }

    public function test_soap_headers_lists_the_sibling_header_blocks_but_not_the_security_header(): void
    {
        $security = $this->securityHeaderInEnvelope();

        $members = DynamicPartMembers::forPart(Part::soapHeaders(), $security);

        static::assertNotNull($members);
        static::assertSame(['Action', 'To'], $this->localNames($members));
    }

    public function test_an_absent_security_header_expands_to_an_empty_list(): void
    {
        static::assertSame([], DynamicPartMembers::forPart(Part::securityHeaderContents(), null));
        static::assertSame([], DynamicPartMembers::forPart(Part::soapHeaders(), null));
    }

    public function test_a_security_header_without_an_element_parent_expands_to_no_soap_headers(): void
    {
        $document = Document::fromXmlString('<wsse:Security xmlns:wsse="'.self::WSSE.'"/>');

        $members = DynamicPartMembers::forPart(
            Part::soapHeaders(),
            $document->locateDocumentElement(),
        );

        static::assertSame([], $members);
    }

    /**
     * @param list<Element> $elements
     *
     * @return list<string>
     */
    private function localNames(array $elements): array
    {
        return array_map(static fn (Element $element): string => (string) $element->localName, $elements);
    }

    /**
     * The wsse:Security header of a full envelope: the Security header is what the enumeration reads, but it
     * has to sit in a real envelope for the soapHeaders case to have siblings to find.
     */
    private function securityHeaderInEnvelope(): Element
    {
        $document = Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.self::SOAP.'"'
            .' xmlns:wsse="'.self::WSSE.'"'
            .' xmlns:wsu="'.self::WSU.'"'
            .' xmlns:ds="'.self::DS.'"'
            .' xmlns:wsa="urn:wsa">'
            .'<soap:Header>'
            .'<wsa:Action>urn:op</wsa:Action>'
            .'<wsse:Security>'
            .'<wsu:Timestamp/>'
            .'<wsse:BinarySecurityToken>x</wsse:BinarySecurityToken>'
            .'<ds:Signature/>'
            .'</wsse:Security>'
            .'<wsa:To>urn:dest</wsa:To>'
            .'</soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );

        $security = $document->toUnsafeDocument()->getElementsByTagNameNS(self::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $security);

        return $security;
    }
}
