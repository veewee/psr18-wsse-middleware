<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SigningPartResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetKind;
use VeeWee\Xml\Dom\Document;

/**
 * Covers SigningPartResolver, the WSSE-layer lowering of Parts to engine Targets: static parts delegate to
 * Part::toTarget, the dynamic parts (securityHeaderContents/soapHeaders) are expanded against the live header
 * with a minted wsu:Id, and a parts list that matches nothing raises the uniform "nothing to sign" fault.
 */
final class SigningPartResolverTest extends TestCase
{
    private const SOAP12 = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_static_parts_lower_to_a_single_target(): void
    {
        $document = $this->envelope('');
        $targets = $this->resolve($document, [Part::body(), Part::element('urn:x', 'Foo'), Part::byId('abc')]);

        static::assertCount(3, $targets);
        static::assertTrue($targets[0]->equals(Target::element(self::SOAP12, 'Body')));
        static::assertTrue($targets[1]->equals(Target::element('urn:x', 'Foo')));
        static::assertTrue($targets[2]->equals(Target::byId('abc')));
    }

    public function test_security_header_contents_expands_to_every_child_targeted_by_minted_id(): void
    {
        $document = $this->envelope('<wsu:Timestamp xmlns:wsu="'.self::WSU.'"/>');
        $targets = $this->resolve($document, [Part::securityHeaderContents()]);

        static::assertCount(1, $targets);
        static::assertSame(TargetKind::Id, $targets[0]->kind());
        $timestamp = $this->only($document, self::WSU, 'Timestamp');
        static::assertSame($targets[0]->id(), $timestamp->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_a_child_id_minted_by_an_earlier_block_is_reused(): void
    {
        $document = $this->envelope('<wsu:Timestamp xmlns:wsu="'.self::WSU.'" wsu:Id="already-here"/>');
        $targets = $this->resolve($document, [Part::securityHeaderContents()]);

        static::assertCount(1, $targets);
        static::assertSame('already-here', $targets[0]->id());
    }

    public function test_soap_headers_expands_to_header_blocks_except_the_security_header(): void
    {
        $document = $this->envelope('', '<wsa:To xmlns:wsa="urn:wsa">urn:svc</wsa:To>');
        $targets = $this->resolve($document, [Part::soapHeaders()]);

        static::assertCount(1, $targets, 'Only wsa:To is targeted; the Security header excludes itself.');
        $to = $this->only($document, 'urn:wsa', 'To');
        static::assertSame($targets[0]->id(), $to->getAttributeNS(self::WSU, 'Id'));
    }

    public function test_a_dynamic_part_matching_nothing_does_not_fail_when_a_static_part_remains(): void
    {
        $document = $this->envelope('');
        $targets = $this->resolve($document, [Part::body(), Part::securityHeaderContents()]);

        static::assertCount(1, $targets);
        static::assertTrue($targets[0]->equals(Target::element(self::SOAP12, 'Body')));
    }

    public function test_it_throws_when_the_whole_parts_list_matches_nothing(): void
    {
        $document = $this->envelope('');

        $this->expectException(WsseHeaderException::class);
        $this->resolve($document, [Part::securityHeaderContents()]);
    }

    /**
     * @param non-empty-list<Part> $parts
     *
     * @return list<Target>
     */
    private function resolve(Document $document, array $parts): array
    {
        return (new SigningPartResolver(new WsuIdMinter()))
            ->resolve($parts, $document, SoapVersion::Soap12, $this->only($document, self::WSSE, 'Security'));
    }

    private function envelope(string $securityChildren, string $otherHeaders = ''): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header>'.$otherHeaders.'<wsse:Security>'.$securityChildren.'</wsse:Security></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function only(Document $document, string $namespace, string $localName): Element
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName) as $element) {
            $found[] = $element;
        }

        static::assertCount(1, $found);
        static::assertInstanceOf(Element::class, $found[0]);

        return $found[0];
    }
}
