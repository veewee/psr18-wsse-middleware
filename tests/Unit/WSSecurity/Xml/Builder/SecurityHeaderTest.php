<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml\Builder;

use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
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

    public function test_for_context_targets_the_header_as_the_profile_says(): void
    {
        $document = $this->envelope(self::SOAP12);
        $context = new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(actorOrRole: 'urn:ours', mustUnderstand: false),
            new ExchangeKeys()
        );

        $security = SecurityHeader::forContext($context)->element();

        static::assertSame('urn:ours', $security->getAttributeNS(self::SOAP12, 'role'));
        static::assertFalse($security->hasAttributeNS(self::SOAP12, 'mustUnderstand'));

        // One value does both jobs: the header this profile targets outbound is the one it calls ours inbound.
        $wire = Document::fromXmlString($document->toXmlString());
        static::assertInstanceOf(
            Element::class,
            SecurityHeader::locate($wire, SoapVersion::Soap12, 'urn:ours'),
        );
        static::assertNull(SecurityHeader::locate($wire, SoapVersion::Soap12));
    }

    public function test_for_context_defaults_to_the_ultimate_receiver_and_must_understand(): void
    {
        $context = new WsseContext($this->envelope(self::SOAP12), SoapVersion::Soap12, new SecurityProfile(), new ExchangeKeys());

        $security = SecurityHeader::forContext($context)->element();

        static::assertSame('1', $security->getAttributeNS(self::SOAP12, 'mustUnderstand'));
        static::assertFalse($security->hasAttributeNS(self::SOAP12, 'role'));
    }

    public function test_for_context_uses_the_soap_11_actor_spelling(): void
    {
        $context = new WsseContext(
            $this->envelope(self::SOAP11),
            SoapVersion::Soap11,
            new SecurityProfile(actorOrRole: 'urn:ours'),
            new ExchangeKeys()
        );

        $security = SecurityHeader::forContext($context)->element();

        static::assertSame('urn:ours', $security->getAttributeNS(self::SOAP11, 'actor'));
        static::assertFalse($security->hasAttributeNS(self::SOAP11, 'role'));
    }

    public function test_locate_finds_the_header_addressed_to_the_configured_actor(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security/>'
            .'<wsse:Security soap:role="urn:ours"><marker/></wsse:Security>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        // Configured as an intermediary, the header naming us is ours; the untargeted one belongs to the
        // ultimate receiver, which we are not.
        $ours = SecurityHeader::locate($document, SoapVersion::Soap12, 'urn:ours');

        static::assertInstanceOf(Element::class, $ours);
        static::assertSame('marker', $ours->firstElementChild?->localName);
    }

    public function test_locate_does_not_accept_another_actors_header(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security soap:role="urn:someone-else"/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        static::assertNull(SecurityHeader::locate($document, SoapVersion::Soap12, 'urn:ours'));
    }

    public function test_locate_still_defaults_to_the_ultimate_receivers_header(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security soap:role="urn:someone-else"/>'
            .'<wsse:Security><marker/></wsse:Security>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        $ours = SecurityHeader::locate($document, SoapVersion::Soap12);

        static::assertInstanceOf(Element::class, $ours);
        static::assertSame('marker', $ours->firstElementChild?->localName);
    }

    public function test_locate_matches_an_actor_containing_quote_characters(): void
    {
        // The actor is interpolated into an xpath predicate, so a value carrying both quote characters must
        // still be matched as a literal rather than changing the expression.
        $actor = 'urn:it\'s "ours"';
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security soap:role="urn:it&apos;s &quot;ours&quot;"><marker/></wsse:Security>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        $ours = SecurityHeader::locate($document, SoapVersion::Soap12, $actor);

        static::assertInstanceOf(Element::class, $ours);
        static::assertSame('marker', $ours->firstElementChild?->localName);
        static::assertNull(SecurityHeader::locate($document, SoapVersion::Soap12, 'urn:something-else'));
    }

    public function test_locate_refuses_two_headers_for_the_same_actor(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
            .'<wsse:Security soap:role="urn:ours"/><wsse:Security soap:role="urn:ours"/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        $this->expectException(WsseHeaderException::class);
        SecurityHeader::locate($document, SoapVersion::Soap12, 'urn:ours');
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

    public function test_it_does_not_write_into_a_header_addressed_to_another_role(): void
    {
        // An envelope crossing an intermediary already carries that hop's header. Writing our tokens into it
        // would hand our credentials, signature or session key to a node that was never the recipient, so a
        // header for us is created alongside rather than the foreign one being reused.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'" soap:role="urn:gateway"/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        $ours = SecurityHeader::locateOrCreate($document, SoapVersion::Soap12)->element();

        static::assertNull($ours->getAttributeNS(self::SOAP12, 'role'));
        static::assertNotNull(SecurityHeader::locate($document, SoapVersion::Soap12));
        static::assertSame(
            'urn:gateway',
            $document->xpath()->query('//*[local-name()="Security"]')->item(0)->getAttributeNS(self::SOAP12, 'role'),
        );
    }

    public function test_it_does_not_readdress_an_existing_ultimate_receiver_header(): void
    {
        // The mirror case: stamping our role onto a header that carries none would re-address every token
        // already inside it, and the ultimate receiver would then find no header of its own.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'"><wsse:UsernameToken/></wsse:Security>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        $ours = SecurityHeader::locateOrCreate($document, SoapVersion::Soap12, actorOrRole: 'urn:gateway')->element();

        static::assertSame('urn:gateway', $ours->getAttributeNS(self::SOAP12, 'role'));
        static::assertCount(0, iterator_to_array($ours->childNodes));

        // The receiver's own header is still addressed to it, and still carries its token.
        $untouched = SecurityHeader::locate($document, SoapVersion::Soap12);
        static::assertNotNull($untouched);
        static::assertSame('UsernameToken', $untouched->firstElementChild?->localName);
    }

    public function test_it_refuses_two_headers_addressed_to_the_same_target_when_writing(): void
    {
        // The outbound side refuses an ambiguous envelope for the same reason the inbound side does: picking
        // one of two headers addressed to us means the choice decides what a peer sees, silently.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'"/>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'"/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        $this->expectException(WsseHeaderException::class);
        SecurityHeader::locateOrCreate($document, SoapVersion::Soap12);
    }

    /**
     * @return iterable<string, array{0: SoapVersion, 1: string, 2: string}>
     */
    public static function reservedSelfTargets(): iterable
    {
        yield 'soap 1.2 role/next' => [SoapVersion::Soap12, self::SOAP12, 'http://www.w3.org/2003/05/soap-envelope/role/next'];
        yield 'soap 1.2 role/ultimateReceiver' => [SoapVersion::Soap12, self::SOAP12, 'http://www.w3.org/2003/05/soap-envelope/role/ultimateReceiver'];
        yield 'soap 1.1 actor/next' => [SoapVersion::Soap11, self::SOAP11, 'http://schemas.xmlsoap.org/soap/actor/next'];
    }

    #[DataProvider('reservedSelfTargets')]
    public function test_a_header_naming_a_reserved_self_target_is_ours(
        SoapVersion $version,
        string $namespace,
        string $reserved,
    ): void {
        // These are the values the specs give for "every node" and "the ultimate receiver". A peer spelling one
        // out is addressing us conformantly, and reading it as another hop's header refused a correct message.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.$namespace.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'" soap:'.$version->actorOrRoleName().'="'.$reserved.'"/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        static::assertNotNull(SecurityHeader::locate($document, $version));
    }

    public function test_a_header_addressed_to_no_one_is_never_ours(): void
    {
        // role/none means no node processes the header, so it is the one reserved value that is not ours.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'" soap:role="http://www.w3.org/2003/05/soap-envelope/role/none"/>'
            .'</soap:Header><soap:Body/></soap:Envelope>'
        );

        static::assertNull(SecurityHeader::locate($document, SoapVersion::Soap12));
    }

    public function test_a_bare_header_and_a_reserved_one_together_are_ambiguous(): void
    {
        // Both are addressed to us, so there is no single answer to which one this receiver must process.
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'"/>'
            .'<wsse:Security xmlns:wsse="'.self::WSSE.'" soap:role="http://www.w3.org/2003/05/soap-envelope/role/next"/>'
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
