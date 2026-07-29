<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use Dom\Element;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdAttribute;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use VeeWee\Xml\Dom\Document;

/**
 * One minter serves every id convention, so every case runs against both shipped attributes: the engine's
 * xml:id default and the wsu:Id the WS-Security profile mandates. Anything that held for the two separate
 * minters this replaces has to hold for both here.
 */
final class AttributeIdMinterTest extends TestCase
{
    private const XML_NS = 'http://www.w3.org/XML/1998/namespace';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    /**
     * @return iterable<string, array{IdAttribute, string, string}>
     */
    public static function attributeProvider(): iterable
    {
        yield 'xml:id' => [IdAttribute::xmlId(), self::XML_NS, 'id'];
        yield 'wsu:Id' => [IdAttribute::of(self::WSU, 'wsu:Id'), self::WSU, 'Id'];
    }

    public function test_it_is_an_id_minter(): void
    {
        static::assertInstanceOf(IdMinter::class, new AttributeIdMinter(IdAttribute::xmlId()));
    }

    #[DataProvider('attributeProvider')]
    public function test_it_mints_and_stamps_its_own_attribute(IdAttribute $attribute, string $namespace, string $localName): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');

        $id = (new AttributeIdMinter($attribute))->mint($a, $document);

        static::assertNotSame('', $id);
        static::assertSame($id, $a->getAttributeNS($namespace, $localName));
    }

    #[DataProvider('attributeProvider')]
    public function test_it_stamps_no_other_convention(IdAttribute $attribute, string $namespace, string $localName): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');

        (new AttributeIdMinter($attribute))->mint($a, $document);

        // The whole point of the parameterization: a minter must write exactly one attribute, not both.
        $other = $namespace === self::WSU ? self::XML_NS : self::WSU;
        $otherLocal = $namespace === self::WSU ? 'id' : 'Id';
        static::assertNull($a->getAttributeNS($other, $otherLocal));
    }

    #[DataProvider('attributeProvider')]
    public function test_minted_ids_are_unique_within_a_document(IdAttribute $attribute, string $namespace, string $localName): void
    {
        $document = $this->document();
        $minter = new AttributeIdMinter($attribute);

        static::assertNotSame(
            $minter->mint($this->element($document, 'a'), $document),
            $minter->mint($this->element($document, 'b'), $document),
        );
    }

    #[DataProvider('attributeProvider')]
    public function test_the_minted_id_is_a_valid_xml_ncname(IdAttribute $attribute, string $namespace, string $localName): void
    {
        $document = $this->document();

        $id = (new AttributeIdMinter($attribute))->mint($this->element($document, 'a'), $document);

        static::assertMatchesRegularExpression('/^[A-Za-z_][A-Za-z0-9_.\-]*$/', $id);
        static::assertStringNotContainsString('#', $id);
    }

    #[DataProvider('attributeProvider')]
    public function test_mint_is_idempotent(IdAttribute $attribute, string $namespace, string $localName): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');
        $minter = new AttributeIdMinter($attribute);

        static::assertSame($minter->mint($a, $document), $minter->mint($a, $document));
    }

    #[DataProvider('attributeProvider')]
    public function test_mint_reuses_an_id_the_element_already_carries(IdAttribute $attribute, string $namespace, string $localName): void
    {
        $document = $this->document();
        $a = $this->element($document, 'a');
        $a->setAttributeNS($namespace, ($namespace === self::WSU ? 'wsu:' : 'xml:').$localName, 'pre-existing');

        static::assertSame('pre-existing', (new AttributeIdMinter($attribute))->mint($a, $document));
    }

    private function document(): Document
    {
        return Document::fromXmlString(
            '<root xmlns="urn:example" xmlns:wsu="'.self::WSU.'"><a/><b/></root>'
        );
    }

    private function element(Document $document, string $localName): Element
    {
        $element = $document->toUnsafeDocument()->getElementsByTagName($localName)->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }
}
