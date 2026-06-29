<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\TrustStore;

final class TrustStoreTest extends TestCase
{
    public function test_it_concatenates_its_anchors_into_a_pem_bundle(): void
    {
        $store = TrustStore::fromCertificates(new Certificate('first-pem'), new Certificate('second-pem'));

        $bundle = $store->toPem();

        static::assertStringContainsString('first-pem', $bundle);
        static::assertStringContainsString('second-pem', $bundle);
    }
}
