<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Fixture\Pkcs12Fixture;

final class CertificateTest extends TestCase
{
    public function test_it_loads_the_leaf_certificate_from_pkcs12_contents(): void
    {
        $fixture = Pkcs12Fixture::create('secret');

        $certificate = Certificate::fromPkcs12($fixture->p12, 'secret');

        static::assertStringContainsString('CERTIFICATE', $certificate->contents());
        static::assertNotSame('', $certificate->toBase64Der());
    }

    public function test_it_loads_the_leaf_certificate_from_a_pkcs12_file(): void
    {
        $fixture = Pkcs12Fixture::create('secret');
        $file = $fixture->writeToTempFile();

        try {
            $certificate = Certificate::fromPkcs12File($file, 'secret');

            static::assertStringContainsString('CERTIFICATE', $certificate->contents());
            static::assertNotSame('', $certificate->toBase64Der());
        } finally {
            @unlink($file);
        }
    }

    public function test_it_rejects_a_wrong_passphrase_without_leaking_it(): void
    {
        $fixture = Pkcs12Fixture::create('secret');

        try {
            Certificate::fromPkcs12($fixture->p12, 'wrong-passphrase');
            static::fail('Expected a Pkcs12Exception to be thrown.');
        } catch (Pkcs12Exception $exception) {
            static::assertStringNotContainsString('wrong-passphrase', $exception->getMessage());
        }
    }
}
