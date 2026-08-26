<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\Pkcs12Exception;
use Soap\Psr18WsseMiddleware\KeyStore\Pkcs12Bundle;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use SoapTest\Psr18WsseMiddleware\Unit\KeyStore\Fixture\Pkcs12Fixture;

final class TrustStorePkcs12Test extends TestCase
{
    public function test_it_builds_anchors_from_the_embedded_ca_chain(): void
    {
        $trustStore = TrustStore::fromPkcs12(Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret')->p12, 'secret'));

        static::assertFalse($trustStore->isEmpty());
        static::assertCount(1, $trustStore->anchors());
        static::assertStringContainsString('CERTIFICATE', $trustStore->anchors()[0]->contents());
    }

    public function test_it_rejects_a_pkcs12_without_a_ca_chain(): void
    {
        $bundle = Pkcs12Bundle::fromString(Pkcs12Fixture::create('secret', withCaChain: false)->p12, 'secret');

        $this->expectException(Pkcs12Exception::class);
        TrustStore::fromPkcs12($bundle);
    }
}
