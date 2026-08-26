<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound\KeyReference;

use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;

final class X509SubjectKeyIdentifierTest extends KeyIdentifierTestCase
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier';
    private const ENCODING_TYPE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    public function test_it_emits_a_key_info_with_the_subject_key_identifier(): void
    {
        $document = $this->document();
        $certificate = $this->certificate();
        $expected = $certificate->info()->subjectKeyIdentifier()->toBase64();

        $keyInfo = (new X509SubjectKeyIdentifier($certificate))
            ->apply($document);

        static::assertSame('KeyInfo', $keyInfo->localName);
        static::assertSame(self::DS, $keyInfo->namespaceURI);

        $str = $this->firstChildElement($keyInfo);
        static::assertSame('SecurityTokenReference', $str->localName);

        $keyIdentifier = $this->firstChildElement($str);
        static::assertSame('KeyIdentifier', $keyIdentifier->localName);
        static::assertSame(self::WSSE, $keyIdentifier->namespaceURI);
        static::assertSame(self::VALUE_TYPE, $keyIdentifier->getAttribute('ValueType'));
        static::assertSame(self::ENCODING_TYPE, $keyIdentifier->getAttribute('EncodingType'));
        static::assertSame($expected, $keyIdentifier->textContent);
    }
}
