<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\IssuerSerial;

final class IssuerSerialTest extends TestCase
{
    public function test_it_exposes_the_issuer_name_and_serial_number(): void
    {
        $issuer = DistinguishedName::fromStructured(['CN' => 'Test CA']);

        $issuerSerial = new IssuerSerial($issuer, '4242');

        static::assertSame('CN=Test CA', $issuerSerial->issuer->toString());
        static::assertSame('4242', $issuerSerial->serialNumber);
    }
}
