<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdAttribute;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * One lookup serves every id convention, so every case runs against both shipped attributes. The XSW hardening
 * that lived on the two separate lookups is pinned here for both: an anchored XPath over its own attribute
 * only, a crafted id treated as a literal, and a duplicate refused as ambiguous rather than resolved.
 */
final class AttributeIdLookupTest extends TestCase
{
    private const XML_NS = 'http://www.w3.org/XML/1998/namespace';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    /**
     * @return iterable<string, array{IdAttribute, string}>
     */
    public static function attributeProvider(): iterable
    {
        yield 'xml:id' => [IdAttribute::xmlId(), 'xml:id'];
        yield 'wsu:Id' => [IdAttribute::of(self::WSU, 'wsu:Id'), 'wsu:Id'];
    }

    public function test_it_is_an_id_lookup(): void
    {
        static::assertInstanceOf(IdLookup::class, new AttributeIdLookup(IdAttribute::xmlId()));
    }

    #[DataProvider('attributeProvider')]
    public function test_it_resolves_the_exact_element_carrying_the_id(IdAttribute $attribute, string $spelling): void
    {
        $document = $this->document($spelling, 'target');
        $expected = $document->toUnsafeDocument()->getElementsByTagName('a')->item(0);

        static::assertSame($expected, (new AttributeIdLookup($attribute))->lookup($document, 'target'));
    }

    #[DataProvider('attributeProvider')]
    public function test_it_throws_when_no_element_carries_the_id(IdAttribute $attribute, string $spelling): void
    {
        $this->expectException(IdReferenceException::class);

        (new AttributeIdLookup($attribute))->lookup($this->document($spelling, 'other'), 'missing');
    }

    #[DataProvider('attributeProvider')]
    public function test_it_ignores_the_other_convention_attribute(IdAttribute $attribute, string $spelling): void
    {
        // A lookup must resolve only its own attribute. Were it to fall back to any id-looking attribute, a
        // message could carry a wsu:Id the verifier reads as an xml:id and address a different element with it.
        $other = $spelling === 'wsu:Id' ? 'xml:id' : 'wsu:Id';

        $this->expectException(IdReferenceException::class);

        (new AttributeIdLookup($attribute))->lookup($this->document($other, 'target'), 'target');
    }

    #[DataProvider('attributeProvider')]
    public function test_it_rejects_a_duplicate_id_as_ambiguous(IdAttribute $attribute, string $spelling): void
    {
        // libxml rejects a duplicate xml:id at parse time, so both cases inject the duplicate onto the live DOM
        // the way an XML Signature Wrapping payload would present it.
        $document = $this->document($spelling, 'dup');
        $b = $document->toUnsafeDocument()->getElementsByTagName('b')->item(0);
        static::assertNotNull($b);
        $b->setAttributeNS($attribute->namespaceUri, $spelling, 'dup');

        $this->expectException(IdReferenceException::class);

        (new AttributeIdLookup($attribute))->lookup($document, 'dup');
    }

    /** A crafted id must be treated as a literal value, never injected into the query. */
    #[DataProvider('attributeProvider')]
    public function test_it_is_not_vulnerable_to_xpath_injection(IdAttribute $attribute, string $spelling): void
    {
        $this->expectException(IdReferenceException::class);

        // Classic injection: would match every element if interpolated unescaped.
        (new AttributeIdLookup($attribute))->lookup($this->document($spelling, 'target'), "x' or '1'='1");
    }

    /**
     * The quote-literal cases run against wsu:Id only, and deliberately so: libxml constrains an xml:id value to
     * an NCName and refuses to load a document where one carries a quote, so the case cannot arise under the
     * engine's own attribute. A wsu:Id is a plain attribute with no such constraint, which is exactly why the
     * literal builder has to be right.
     */
    public function test_it_handles_an_id_containing_a_single_quote_as_a_literal(): void
    {
        $document = $this->document('wsu:Id', 'it&apos;s-me');

        $element = (new AttributeIdLookup($this->wsuId()))->lookup($document, "it's-me");

        static::assertSame('a', $element->localName);
    }

    /** Exercises the concat() branch of the literal builder: a value containing BOTH quote characters. */
    public function test_it_handles_an_id_containing_both_quote_types_as_a_literal(): void
    {
        $document = $this->document('wsu:Id', 'a&apos;&quot;b');

        $element = (new AttributeIdLookup($this->wsuId()))->lookup($document, 'a\'"b');

        static::assertSame('a', $element->localName);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableNameProvider(): iterable
    {
        yield 'trailing colon, no local part' => ['wsu:'];
        yield 'leading colon, no prefix' => [':Id'];
        yield 'more than one colon' => ['a:b:c'];
        yield 'empty' => [''];
    }

    /**
     * The local name is derived from the qualified one so the two spellings cannot disagree. That only holds if
     * the input is a name it can be derived from: "wsu:" would yield an empty local name and "a:b:c" a local name
     * carrying a colon, and either would address no attribute at all while still looking configured.
     */
    #[DataProvider('unusableNameProvider')]
    public function test_it_refuses_a_name_it_cannot_derive_a_local_part_from(string $qualifiedName): void
    {
        $this->expectException(InvalidArgumentException::class);

        IdAttribute::of(self::WSU, $qualifiedName);
    }

    private function wsuId(): IdAttribute
    {
        return IdAttribute::of(self::WSU, 'wsu:Id');
    }

    private function document(string $spelling, string $value): Document
    {
        return Document::fromXmlString(
            '<root xmlns="urn:example" xmlns:wsu="'.self::WSU.'">'
            .'<a '.$spelling.'="'.$value.'"/><b/></root>'
        );
    }
}
