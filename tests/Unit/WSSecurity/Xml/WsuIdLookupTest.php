<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdLookup;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use VeeWee\Xml\Dom\Document;

/**
 * The WS-Security profile references a part by wsu:Id, and a ds:Signature additionally by the native Id that
 * XML Signature declares on it. The second spelling is what makes an endorsed message a peer sent verifiable:
 * WSS4J and CXF write Id="SIG-..." on the element and the endorsing signature references that.
 */
final class WsuIdLookupTest extends TestCase
{
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_it_resolves_a_part_by_its_wsu_id(): void
    {
        $document = $this->envelope('<tns:Body xmlns:tns="urn:x" wsu:Id="the-body" xmlns:wsu="'.self::WSU.'"/>');

        $element = (new WsuIdLookup())->lookup($document, 'the-body');

        static::assertSame('the-body', $element->getAttributeNS(self::WSU, 'Id'));
    }

    /**
     * The reference an endorsement makes. Without this the one reference that matters on an endorsed message
     * cannot be resolved at all, so the message is unverifiable rather than merely unusual.
     */
    public function test_it_resolves_a_signature_by_the_native_id_xml_signature_declares(): void
    {
        $document = $this->envelope('<ds:Signature xmlns:ds="'.self::DS.'" Id="SIG-1"/>');

        $element = (new WsuIdLookup())->lookup($document, 'SIG-1');

        static::assertSame('Signature', $element->localName);
    }

    /**
     * Narrow to that element on purpose. A bare Id elsewhere is an attribute this profile never writes, so
     * honouring it would let a reference reach an element of a peer's choosing for no interop gain.
     */
    public function test_it_does_not_resolve_a_bare_id_on_anything_else(): void
    {
        $document = $this->envelope('<tns:Decoy xmlns:tns="urn:x" Id="SIG-1"/>');

        $this->expectException(IdReferenceException::class);
        $this->expectExceptionMessage('No element found for id "SIG-1"');
        (new WsuIdLookup())->lookup($document, 'SIG-1');
    }

    /**
     * Both spellings are matched in one query, so uniqueness spans them: an id carried once each way is
     * ambiguous rather than resolved to whichever the implementation happened to try first.
     */
    public function test_an_id_carried_under_both_spellings_is_ambiguous(): void
    {
        $document = $this->envelope(
            '<ds:Signature xmlns:ds="'.self::DS.'" Id="SIG-1"/>'
            .'<tns:Part xmlns:tns="urn:x" wsu:Id="SIG-1" xmlns:wsu="'.self::WSU.'"/>',
        );

        $this->expectException(IdReferenceException::class);
        $this->expectExceptionMessage('ambiguous');
        (new WsuIdLookup())->lookup($document, 'SIG-1');
    }

    public function test_a_duplicated_signature_id_is_ambiguous_rather_than_the_first_match(): void
    {
        $document = $this->envelope(
            '<ds:Signature xmlns:ds="'.self::DS.'" Id="SIG-1"/>'
            .'<ds:Signature xmlns:ds="'.self::DS.'" Id="SIG-1"/>',
        );

        $this->expectException(IdReferenceException::class);
        $this->expectExceptionMessage('ambiguous');
        (new WsuIdLookup())->lookup($document, 'SIG-1');
    }

    private function envelope(string $children): Document
    {
        return Document::fromXmlString('<root>'.$children.'</root>');
    }
}
