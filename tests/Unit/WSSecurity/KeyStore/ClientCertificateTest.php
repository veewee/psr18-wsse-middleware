<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\ClientCertificate;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Fixture\Pkcs12Fixture;

final class ClientCertificateTest extends TestCase
{
    public function test_it_loads_a_client_certificate_from_pkcs12_contents(): void
    {
        $fixture = Pkcs12Fixture::create('secret');

        $clientCertificate = ClientCertificate::fromPkcs12($fixture->p12, 'secret');

        static::assertStringContainsString('PRIVATE KEY', $clientCertificate->privateKey()->contents());
        static::assertStringContainsString('CERTIFICATE', $clientCertificate->publicCertificate()->contents());
    }

    public function test_it_loads_a_client_certificate_from_a_pkcs12_file(): void
    {
        $fixture = Pkcs12Fixture::create('secret');
        $file = $fixture->writeToTempFile();

        try {
            $clientCertificate = ClientCertificate::fromPkcs12File($file, 'secret');

            static::assertStringContainsString('PRIVATE KEY', $clientCertificate->privateKey()->contents());
            static::assertStringContainsString('CERTIFICATE', $clientCertificate->publicCertificate()->contents());
        } finally {
            @unlink($file);
        }
    }

    public function test_it_rejects_a_wrong_passphrase_without_leaking_it(): void
    {
        $fixture = Pkcs12Fixture::create('secret');

        try {
            ClientCertificate::fromPkcs12($fixture->p12, 'wrong-passphrase');
            static::fail('Expected a Pkcs12Exception to be thrown.');
        } catch (Pkcs12Exception $exception) {
            static::assertStringNotContainsString('wrong-passphrase', $exception->getMessage());
        }
    }
}
