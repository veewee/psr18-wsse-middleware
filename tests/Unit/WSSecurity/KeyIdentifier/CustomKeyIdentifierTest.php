<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyIdentifier;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\CustomKeyIdentifier;

final class CustomKeyIdentifierTest extends KeyIdentifierTestCase
{
    public function test_it_emits_a_key_identifier_with_the_supplied_values(): void
    {
        $document = $this->document();

        $keyInfo = (new CustomKeyIdentifier('ZW5jb2RlZA==', 'urn:custom-value-type', 'urn:custom-encoding'))
            ->apply($document, $this->certificate());

        static::assertSame('KeyInfo', $keyInfo->localName);
        static::assertSame(self::DS, $keyInfo->namespaceURI);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame('SecurityTokenReference', $str->localName);

        $keyIdentifier = $this->firstChildElement($str);
        static::assertSame('KeyIdentifier', $keyIdentifier->localName);
        static::assertSame(self::WSSE, $keyIdentifier->namespaceURI);
        static::assertSame('urn:custom-value-type', $keyIdentifier->getAttribute('ValueType'));
        static::assertSame('urn:custom-encoding', $keyIdentifier->getAttribute('EncodingType'));
        static::assertSame('ZW5jb2RlZA==', $keyIdentifier->textContent);
    }

    public function test_it_rejects_an_empty_value_type(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new CustomKeyIdentifier('ZW5jb2RlZA==', '', 'urn:custom-encoding');
    }

    public function test_it_rejects_an_empty_encoded_value(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new CustomKeyIdentifier('', 'urn:custom-value-type', 'urn:custom-encoding');
    }

    public function test_it_rejects_an_empty_encoding_type(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new CustomKeyIdentifier('ZW5jb2RlZA==', 'urn:custom-value-type', '');
    }
}
