<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound\KeyReference;

use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;

final class ThumbprintKeyIdentifierTest extends KeyIdentifierTestCase
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1';
    private const ENCODING_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    public function test_it_emits_a_wsse11_key_identifier_with_the_sha1_thumbprint(): void
    {
        $document = $this->document();
        $certificate = $this->certificate();
        $expected = $certificate->info()->thumbprintSha1()->toBase64();

        $keyInfo = (new ThumbprintKeyIdentifier())
            ->apply($document, $certificate);

        static::assertSame('KeyInfo', $keyInfo->localName);
        static::assertSame(self::DS, $keyInfo->namespaceURI);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame('SecurityTokenReference', $str->localName);
        static::assertSame(self::WSSE, $str->namespaceURI);

        $keyIdentifier = $this->firstChildElement($str);
        static::assertSame('KeyIdentifier', $keyIdentifier->localName);
        static::assertSame(self::WSSE11, $keyIdentifier->namespaceURI);
        static::assertSame(self::VALUE_TYPE, $keyIdentifier->getAttribute('ValueType'));
        static::assertSame(self::ENCODING_TYPE, $keyIdentifier->getAttribute('EncodingType'));
        static::assertSame($expected, $keyIdentifier->textContent);
    }
}
