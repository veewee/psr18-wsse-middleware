<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ReferenceListBuilder;
use VeeWee\Xml\Dom\Document;

final class ReferenceListBuilderTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    public function test_it_names_every_encrypted_part_in_document_order(): void
    {
        $document = Document::fromXmlString('<root/>');

        $referenceList = (new ReferenceListBuilder())->build($document, ['id-one', 'id-two']);

        static::assertSame('ReferenceList', $referenceList->localName);
        static::assertSame(self::XENC, $referenceList->namespaceURI);

        $references = $referenceList->getElementsByTagNameNS(self::XENC, 'DataReference');
        static::assertSame(2, $references->count());
        static::assertSame('#id-one', $references->item(0)?->getAttribute('URI'));
        static::assertSame('#id-two', $references->item(1)?->getAttribute('URI'));
    }

    /**
     * Detached, so the caller decides where it goes. Nesting it in the key is what the shared-key shape cannot
     * do, since the key is written before anything has been encrypted.
     */
    public function test_it_returns_a_detached_element(): void
    {
        $document = Document::fromXmlString('<root/>');

        $referenceList = (new ReferenceListBuilder())->build($document, ['id-one']);

        static::assertNull($referenceList->parentNode);
        static::assertInstanceOf(Element::class, $referenceList);
    }
}
