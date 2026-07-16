<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Xml\Locator;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

final class WsuIdLookupTest extends TestCase
{
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    private function document(): Document
    {
        return Document::fromXmlString(
            '<root xmlns:wsu="'.self::WSU.'"><a wsu:Id="target"/><b/></root>'
        );
    }

    public function test_it_is_an_id_lookup(): void
    {
        static::assertInstanceOf(IdLookup::class, new WsuIdLookup());
    }

    public function test_it_resolves_the_exact_element_carrying_the_wsu_id(): void
    {
        $document = $this->document();
        $expected = $document->toUnsafeDocument()->getElementsByTagName('a')->item(0);

        static::assertSame($expected, (new WsuIdLookup())->lookup($document, 'target'));
    }

    public function test_it_throws_when_no_element_carries_the_id(): void
    {
        $this->expectException(IdReferenceException::class);

        (new WsuIdLookup())->lookup($this->document(), 'missing');
    }

    public function test_it_rejects_a_duplicate_id_as_ambiguous(): void
    {
        $document = Document::fromXmlString(
            '<root xmlns:wsu="'.self::WSU.'"><a wsu:Id="dup"/><b wsu:Id="dup"/></root>'
        );

        $this->expectException(IdReferenceException::class);

        (new WsuIdLookup())->lookup($document, 'dup');
    }
}
