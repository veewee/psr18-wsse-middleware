<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdConvention;
use VeeWee\Xml\Dom\Document;

/**
 * A convention hands over both halves of an id convention at once, which is the whole reason it exists: the
 * engine used to take a minter and a lookup as two independent arguments, so a caller could mint wsu:Id and
 * resolve xml:id and produce a signature whose references nobody could follow.
 *
 * Each shipped convention is pinned two ways: what it mints, it resolves; and what it mints, the other
 * convention does not resolve. The second half is what would have caught the mismatch.
 */
final class IdConventionTest extends TestCase
{
    /**
     * @return iterable<string, array{IdConvention, IdConvention}>
     */
    public static function conventionProvider(): iterable
    {
        yield 'xml:id' => [AttributeIdConvention::xmlId(), new WsuIdConvention()];
        yield 'wsu:Id' => [new WsuIdConvention(), AttributeIdConvention::xmlId()];
    }

    #[DataProvider('conventionProvider')]
    public function test_what_a_convention_mints_it_resolves(IdConvention $convention, IdConvention $other): void
    {
        $document = $this->document();
        $target = $this->element($document, 'a');

        $id = $convention->minter()->mint($target, $document);

        static::assertSame($target, $convention->lookup()->lookup($document, $id));
    }

    #[DataProvider('conventionProvider')]
    public function test_the_other_convention_cannot_resolve_it(IdConvention $convention, IdConvention $other): void
    {
        $document = $this->document();
        $id = $convention->minter()->mint($this->element($document, 'a'), $document);

        // Crossing the halves is what the two-argument seam allowed. It fails exactly here, which is why the
        // seam now takes the pair.
        $this->expectException(IdReferenceException::class);
        $other->lookup()->lookup($document, $id);
    }

    #[DataProvider('conventionProvider')]
    public function test_a_convention_hands_back_the_same_pair_each_time(IdConvention $convention, IdConvention $other): void
    {
        // The halves are built once from one attribute, so nothing can hand out a minter and a lookup that were
        // derived from different values.
        static::assertSame($convention->minter(), $convention->minter());
        static::assertSame($convention->lookup(), $convention->lookup());
    }

    private function document(): Document
    {
        return Document::fromXmlString(
            '<root xmlns="urn:example" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><a/><b/></root>'
        );
    }

    private function element(Document $document, string $localName): Element
    {
        $element = $document->toUnsafeDocument()->getElementsByTagName($localName)->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }
}
