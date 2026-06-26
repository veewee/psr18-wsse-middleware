<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyIdentifier;

use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\IssuerSerialKeyIdentifier;

final class IssuerSerialKeyIdentifierTest extends KeyIdentifierTestCase
{
    public function test_it_emits_a_key_info_with_issuer_name_and_serial_number(): void
    {
        $document = $this->document();
        $certificate = $this->certificate();
        $expected = (new CertificateFieldExtractor())->issuerSerial($certificate);

        $keyInfo = (new IssuerSerialKeyIdentifier(new CertificateFieldExtractor()))
            ->apply($document, $certificate);

        static::assertSame('KeyInfo', $keyInfo->localName);
        static::assertSame(self::DS, $keyInfo->namespaceURI);

        $x509Data = $this->firstChildElement($keyInfo);
        static::assertSame('X509Data', $x509Data->localName);
        static::assertSame(self::DS, $x509Data->namespaceURI);

        $issuerSerial = $this->firstChildElement($x509Data);
        static::assertSame('X509IssuerSerial', $issuerSerial->localName);
        static::assertSame(self::DS, $issuerSerial->namespaceURI);

        $issuerName = $this->childByLocalName($issuerSerial, 'X509IssuerName');
        static::assertSame(self::DS, $issuerName->namespaceURI);
        static::assertSame($expected['issuerName'], $issuerName->textContent);

        $serialNumber = $this->childByLocalName($issuerSerial, 'X509SerialNumber');
        static::assertSame(self::DS, $serialNumber->namespaceURI);
        static::assertSame($expected['serialNumber'], $serialNumber->textContent);
        static::assertSame('4242', $serialNumber->textContent);
    }

    public function test_it_does_not_wrap_the_reference_in_a_security_token_reference(): void
    {
        $keyInfo = (new IssuerSerialKeyIdentifier(new CertificateFieldExtractor()))
            ->apply($this->document(), $this->certificate());

        static::assertSame(0, $keyInfo->getElementsByTagNameNS(self::WSSE, 'SecurityTokenReference')->length);
    }
}
