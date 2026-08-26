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

        static::assertSame(['cid:a@example.com'], XopInclude::hrefsIn($document, $this->target($document)));
    }

    public function test_it_finds_an_include_nested_below_the_element(): void
    {
        $document = $this->document(
            '<data id="target"><wrap><xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></wrap></data>',
        );

        static::assertSame(['cid:a@example.com'], XopInclude::hrefsIn($document, $this->target($document)));
    }

    public function test_it_reports_nothing_for_an_element_carrying_its_own_value(): void
    {
        $document = $this->document('<data id="target">bWVvdw==</data>');

        static::assertSame([], XopInclude::hrefsIn($document, $this->target($document)));
    }

    public function test_it_does_not_look_outside_the_element(): void
    {
        // The caller asks about one encryption target, so an include belonging to a sibling is not its
        // answer: reporting it would refuse an element whose own bytes travel in the message.
        $document = $this->document(
            '<root><data id="target">inline</data>'
            .'<other><xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></other></root>',
        );

        static::assertSame([], XopInclude::hrefsIn($document, $this->target($document)));
    }

    public function test_it_matches_on_the_namespace_rather_than_the_local_name(): void
    {
        // An element a peer happens to have called Include is not an optimized-content placeholder, and
        // refusing to encrypt it would be a refusal nothing in the message justifies.
        $document = $this->document(
            '<data id="target"><Include xmlns="urn:example:not-xop" href="cid:a@example.com"/></data>',
        );

        static::assertSame([], XopInclude::hrefsIn($document, $this->target($document)));
    }

    public function test_it_matches_whatever_prefix_the_message_bound(): void
    {
        $document = $this->document(
            '<data id="target"><ns0:Include xmlns:ns0="'.self::XOP.'" href="cid:a@example.com"/></data>',
        );

        static::assertSame(['cid:a@example.com'], XopInclude::hrefsIn($document, $this->target($document)));
    }

    public function test_it_reports_every_href_in_document_order(): void
    {
        $document = $this->document(
            '<data id="target">'
            .'<xop:Include xmlns:xop="'.self::XOP.'" href="cid:first@example.com"/>'
            .'<wrap><xop:Include xmlns:xop="'.self::XOP.'" href="cid:second@example.com"/></wrap>'
            .'</data>',
        );

        static::assertSame(
            ['cid:first@example.com', 'cid:second@example.com'],
            XopInclude::hrefsIn($document, $this->target($document)),
        );
    }

    public function test_it_reports_an_include_without_an_href_as_an_empty_reference(): void
    {
        // An include naming nothing can never match a supplied part, so it must still be reported: dropping
        // it would let an element hold a placeholder that every caller then reads as absent.
        $document = $this->document(
            '<data id="target"><xop:Include xmlns:xop="'.self::XOP.'"/></data>',
        );

        static::assertSame([''], XopInclude::hrefsIn($document, $this->target($document)));
    }

    public function test_it_reads_a_sole_include_as_the_elements_whole_content(): void
    {
        $document = $this->document(
            '<data id="target"><xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></data>',
        );

        static::assertSame('cid:a@example.com', XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_a_sole_include_through_surrounding_whitespace(): void
    {
        // Pretty-printed XML is the normal case on the wire, and a peer ignores text nodes here.
        $document = $this->document(
            '<data id="target">'."\n    ".'<xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/>'."\n".'</data>',
        );

        static::assertSame('cid:a@example.com', XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_no_sole_include_for_an_element_carrying_its_own_value(): void
    {
        $document = $this->document('<data id="target">bWVvdw==</data>');

        static::assertNull(XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_no_sole_include_when_text_travels_beside_it(): void
    {
        // Text plus a pointer is ambiguity a peer chooses the meaning of, so neither reading is offered.
        $document = $this->document(
            '<data id="target">bWVvdw==<xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></data>',
        );

        static::assertNull(XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_no_sole_include_when_a_second_one_travels_beside_it(): void
    {
        $document = $this->document(
            '<data id="target">'
            .'<xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/>'
            .'<xop:Include xmlns:xop="'.self::XOP.'" href="cid:b@example.com"/>'
            .'</data>',
        );

        static::assertNull(XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_no_sole_include_when_a_comment_travels_beside_it(): void
    {
        // A comment is not whitespace, and this element's content is not a place to be lenient.
        $document = $this->document(
            '<data id="target"><!-- why --><xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></data>',
        );

        static::assertNull(XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_no_sole_include_for_one_nested_deeper(): void
    {
        // Only the element's own content stands in for its value. A pointer one level down is describing
        // something else, and resolving it would put bytes where the message never said they belong.
        $document = $this->document(
            '<data id="target"><wrap><xop:Include xmlns:xop="'.self::XOP.'" href="cid:a@example.com"/></wrap></data>',
        );

        static::assertNull(XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_no_sole_include_for_one_carrying_no_href(): void
    {
        $document = $this->document(
            '<data id="target"><xop:Include xmlns:xop="'.self::XOP.'"/></data>',
        );

        static::assertNull(XopInclude::soleHref($this->target($document)));
    }

    public function test_it_reads_no_sole_include_for_an_element_named_include_in_another_namespace(): void
    {
        $document = $this->document(
            '<data id="target"><Include xmlns="urn:example:not-xop" href="cid:a@example.com"/></data>',
        );

        static::assertNull(XopInclude::soleHref($this->target($document)));
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
