<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\Pkcs12Exception;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Fixture\Pkcs12Fixture;

final class TrustStorePkcs12Test extends TestCase
{
    public function test_it_builds_anchors_from_the_embedded_ca_chain(): void
    {
        $fixture = Pkcs12Fixture::create('secret');

        $trustStore = TrustStore::fromPkcs12($fixture->p12, 'secret');

        static::assertFalse($trustStore->isEmpty());
        static::assertCount(1, $trustStore->anchors());
        static::assertStringContainsString('CERTIFICATE', $trustStore->anchors()[0]->contents());
    }

    public function test_it_builds_anchors_from_a_pkcs12_file(): void
    {
        $fixture = Pkcs12Fixture::create('secret');
        $file = $fixture->writeToTempFile();

        try {
            $trustStore = TrustStore::fromPkcs12File($file, 'secret');

            static::assertFalse($trustStore->isEmpty());
            static::assertCount(1, $trustStore->anchors());
        } finally {
            @unlink($file);
        }
    }

    public function test_it_rejects_a_pkcs12_without_a_ca_chain(): void
    {
        $fixture = Pkcs12Fixture::create('secret', withCaChain: false);

        $this->expectException(Pkcs12Exception::class);
        TrustStore::fromPkcs12($fixture->p12, 'secret');
    }

    public function test_it_rejects_a_wrong_passphrase_without_leaking_it(): void
    {
        $fixture = Pkcs12Fixture::create('secret');

        try {
            TrustStore::fromPkcs12($fixture->p12, 'wrong-passphrase');
            static::fail('Expected a Pkcs12Exception to be thrown.');
        } catch (Pkcs12Exception $exception) {
            static::assertStringNotContainsString('wrong-passphrase', $exception->getMessage());
        }
    }
}
