<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Pkcs12Bundle;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Fixture\Pkcs12Fixture;

final class CertificateTest extends TestCase
{
    public function test_it_takes_the_leaf_certificate_from_a_pkcs12_bundle(): void
    {
        $certificate = Certificate::fromPkcs12(Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret')->p12, 'secret'));

        static::assertStringContainsString('CERTIFICATE', $certificate->contents());
        static::assertNotSame('', $certificate->toBase64Der());
    }

    public function test_it_reads_its_metadata(): void
    {
        $certificate = Certificate::fromPkcs12(Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret')->p12, 'secret'));

        static::assertStringContainsString('CN=Test Leaf', $certificate->info()->subject()->toString());
    }

    public function test_it_parses_its_metadata_once_per_instance(): void
    {
        $certificate = Certificate::fromPkcs12(Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret')->p12, 'secret'));

        static::assertSame($certificate->info(), $certificate->info());
    }

    public function test_it_round_trips_a_base64_der_certificate(): void
    {
        $certificate = Certificate::fromPkcs12(Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret')->p12, 'secret'));

        $rebuilt = Certificate::fromBase64Der($certificate->toBase64Der());

        static::assertSame($certificate->toBase64Der(), $rebuilt->toBase64Der());
    }

    public function test_it_rejects_invalid_base64_der(): void
    {
        $this->expectException(WsseHeaderException::class);
        Certificate::fromBase64Der('!!!not base64!!!');
    }
}
