<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Xml;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\XopInclude;
use VeeWee\Xml\Dom\Document;

final class XopIncludeTest extends TestCase
{
    private const XOP = 'http://www.w3.org/2004/08/xop/include';

    public function test_it_finds_an_include_the_element_itself_is(): void
    {
        $document = $this->document(
            '<xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com" id="target"/>',
        );

        static::assertTrue(XopInclude::presentIn($document, $this->target($document)));
    }

    public function test_it_finds_an_include_nested_below_the_element(): void
    {
        $document = $this->document(
            '<data id="target"><wrap><xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></wrap></data>',
        );

        static::assertTrue(XopInclude::presentIn($document, $this->target($document)));
    }

    public function test_it_reports_nothing_for_an_element_carrying_its_own_value(): void
    {
        $document = $this->document('<data id="target">bWVvdw==</data>');

        static::assertFalse(XopInclude::presentIn($document, $this->target($document)));
    }

    public function test_it_does_not_look_outside_the_element(): void
    {
        // The caller asks about one encryption target, so an include belonging to a sibling is not its
        // answer: reporting it would refuse an element whose own bytes travel in the message.
        $document = $this->document(
            '<root><data id="target">inline</data>'
            .'<other><xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></other></root>',
        );

        static::assertFalse(XopInclude::presentIn($document, $this->target($document)));
    }

    public function test_it_matches_on_the_namespace_rather_than_the_local_name(): void
    {
        // An element a peer happens to have called Include is not an optimized-content placeholder, and
        // refusing to encrypt it would be a refusal nothing in the message justifies.
        $document = $this->document(
            '<data id="target"><Include xmlns="urn:example:not-xop" href="cid:a@example.com"/></data>',
        );

        static::assertFalse(XopInclude::presentIn($document, $this->target($document)));
    }

    public function test_it_matches_whatever_prefix_the_message_bound(): void
    {
        $document = $this->document(
            '<data id="target"><ns0:Include xmlns:ns0="'.self::XOP.'" href="cid:a@example.com"/></data>',
        );

        static::assertTrue(XopInclude::presentIn($document, $this->target($document)));
    }

    private function document(string $xml): Document
    {
        return Document::fromXmlString('<?xml version="1.0"?>'.$xml);
    }

    private function target(Document $document): Element
    {
        return Query::elements($document, '//*[@id="target"]')->expectFirst();
    }
}
