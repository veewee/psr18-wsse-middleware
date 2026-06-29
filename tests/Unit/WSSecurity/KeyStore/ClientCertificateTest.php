<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Pkcs12Bundle;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Fixture\Pkcs12Fixture;

final class ClientCertificateTest extends TestCase
{
    public function test_it_takes_the_certificate_and_key_from_a_pkcs12_bundle(): void
    {
        $clientCertificate = ClientCertificate::fromPkcs12(
            Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret')->p12, 'secret'),
        );

        static::assertStringContainsString('PRIVATE KEY', $clientCertificate->privateKey()->contents());
        static::assertStringContainsString('CERTIFICATE', $clientCertificate->publicCertificate()->contents());
    }
}
