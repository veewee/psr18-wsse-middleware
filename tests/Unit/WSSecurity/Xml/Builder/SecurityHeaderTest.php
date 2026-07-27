<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml\Builder;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

final class SecurityHeaderTest extends TestCase
{
    private const SOAP11 = 'http://schemas.xmlsoap.org/soap/envelope/';
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

    private function envelope(string $soapNs, bool $withHeader = false): Document
    {
        $header = $withHeader ? '<soap:Header/>' : '';

        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.$soapNs.'">'.$header.'<soap:Body/></soap:Envelope>'
        );
    }

    /** @return list<Element> */
    private function elements(Document $document, string $namespace, string $localName): array
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName) as $element) {
            $found[] = $element;
        }

        return $found;
    }

    public function test_it_creates_the_security_element_when_absent(): void
    {
        $document = $this->envelope(self::SOAP11, withHeader: true);

        $header = SecurityHeader::locateOrCreate($document, SoapVersion::Soap11);

        static::assertCount(1, $this->elements($document, self::WSSE, 'Security'));
        static::assertSame('Security', $header->element()->localName);
        static::assertSame(self::WSSE, $header->element()->namespaceURI);
    }

    public function test_it_creates_the_soap_header_when_absent(): void
    {
        $document = $this->envelope(self::SOAP12);

        SecurityHeader::locateOrCreate($document, SoapVersion::Soap12);

        static::assertCount(1, $this->elements($document, self::SOAP12, 'Header'));
        static::assertCount(1, $this->elements($document, self::WSSE, 'Security'));
    }

    public function test_it_locates_an_existing_security_element(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header><wsse:Security/></soap:Header><soap:Body/></soap:Envelope>'
        );

        $existing = $this->elements($document, self::WSSE, 'Security')[0];

        $header = SecurityHeader::locateOrCreate($document, SoapVersion::Soap12);

        static::assertCount(1, $this->elements($document, self::WSSE, 'Security'));
        static::assertSame($existing, $header->element());
    }

    public function test_it_is_idempotent_on_locate(): void
    {
        $document = $this->envelope(self::SOAP12, withHeader: true);

        SecurityHeader::locateOrCreate($document, SoapVersion::Soap12);
        SecurityHeader::locateOrCreate($document, SoapVersion::Soap12);

        static::assertCount(1, $this->elements($document, self::WSSE, 'Security'));
    }

    public function test_it_attaches_must_understand_on_soap_11(): void
    {
        $document = $this->envelope(self::SOAP11, withHeader: true);

        $header = SecurityHeader::locateOrCreate($document, SoapVersion::Soap11, mustUnderstand: true);

        static::assertSame('1', $header->element()->getAttributeNS(self::SOAP11, 'mustUnderstand'));
    }

    public function test_it_attaches_must_understand_on_soap_12(): void
    {
        $document = $this->envelope(self::SOAP12, withHeader: true);

        $header = SecurityHeader::locateOrCreate($document, SoapVersion::Soap12, mustUnderstand: true);

        static::assertSame('1', $header->element()->getAttributeNS(self::SOAP12, 'mustUnderstand'));
    }

    public function test_it_omits_must_understand_when_disabled(): void
    {
        $document = $this->envelope(self::SOAP12, withHeader: true);

        $header = SecurityHeader::locateOrCreate($document, SoapVersion::Soap12, mustUnderstand: false);

        static::assertFalse($header->element()->hasAttributeNS(self::SOAP12, 'mustUnderstand'));
    }

    public function test_it_attaches_actor_on_soap_11(): void
    {
        $document = $this->envelope(self::SOAP11, withHeader: true);

        $header = SecurityHeader::locateOrCreate(
            $document,
            SoapVersion::Soap11,
            actorOrRole: 'urn:receiver',
        );

        static::assertSame('urn:receiver', $header->element()->getAttributeNS(self::SOAP11, 'actor'));
        static::assertFalse($header->element()->hasAttributeNS(self::SOAP11, 'role'));
    }

    public function test_it_attaches_role_on_soap_12(): void
    {
        $document = $this->envelope(self::SOAP12, withHeader: true);

        $header = SecurityHeader::locateOrCreate(
            $document,
            SoapVersion::Soap12,
            actorOrRole: 'urn:receiver',
        );

        static::assertSame('urn:receiver', $header->element()->getAttributeNS(self::SOAP12, 'role'));
        static::assertFalse($header->element()->hasAttributeNS(self::SOAP12, 'actor'));
    }

    public function test_locate_returns_null_when_no_security_header_is_present(): void
    {
        $document = $this->envelope(self::SOAP12, withHeader: true);

        static::assertNull(SecurityHeader::locate($document, SoapVersion::Soap12));
    }

    public function test_locate_finds_the_header_targeted_at_the_ultimate_receiver(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header><wsse:Security/></soap:Header><soap:Body/></soap:Envelope>'
        );

        static::assertSame(
            $this->elements($document, self::WSSE, 'Security')[0],
            SecurityHeader::locate($document, SoapVersion::Soap12),
        );
    }

    public function test_locate_ignores_a_security_element_planted_outside_the_soap_header(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header/><soap:Body><wsse:Security/></soap:Body></soap:Envelope>'
        );

        static::assertNull(SecurityHeader::locate($document, SoapVersion::Soap12));
    }

    public function test_locate_ignores_a_header_targeted_at_another_role(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security soap:role="urn:intermediary"/><wsse:Security/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        static::assertSame(
            $this->elements($document, self::WSSE, 'Security')[1],
            SecurityHeader::locate($document, SoapVersion::Soap12),
        );
    }

    public function test_locate_ignores_a_header_targeted_at_another_actor_on_soap_11(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP11.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security soap:actor="urn:intermediary"/><wsse:Security/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        static::assertSame(
            $this->elements($document, self::WSSE, 'Security')[1],
            SecurityHeader::locate($document, SoapVersion::Soap11),
        );
    }

    public function test_locate_rejects_a_second_header_for_the_ultimate_receiver(): void
    {
        // An injected empty header must not be able to stand in for the real one: were it picked, every
        // dynamic required part would expand against an empty header and be vacuously satisfied.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security/><wsse:Security><wsse:UsernameToken/></wsse:Security>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        $this->expectException(WsseHeaderException::class);

        SecurityHeader::locate($document, SoapVersion::Soap12);
    }

    public function test_append_children_attaches_and_reorders_nodes(): void
    {
        $document = $this->envelope(self::SOAP12, withHeader: true);
        $wsu = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

        $header = SecurityHeader::locateOrCreate($document, SoapVersion::Soap12);

        // Append in non-canonical order: Timestamp before BinarySecurityToken.
        $header->appendChildren(
            namespaced_element($wsu, 'wsu:Timestamp', value('')),
            namespaced_element(self::WSSE, 'wsse:BinarySecurityToken', value('')),
        );

        $children = [];
        foreach ($header->element()->childNodes as $child) {
            if ($child instanceof Element) {
                $children[] = $child->localName;
            }
        }

        static::assertSame(['BinarySecurityToken', 'Timestamp'], $children);
    }

    public function test_append_children_with_no_builders_is_a_noop(): void
    {
        $document = $this->envelope(self::SOAP12, withHeader: true);

        $header = SecurityHeader::locateOrCreate($document, SoapVersion::Soap12);
        $header->appendChildren();

        static::assertCount(0, iterator_to_array($header->element()->childNodes));
    }
}
