<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

final class TrustStoreTest extends TestCase
{
    public function test_it_concatenates_its_anchors_into_a_pem_bundle(): void
    {
        $store = TrustStore::fromCertificates(new Certificate('first-pem'), new Certificate('second-pem'));

        $bundle = $store->toPem()->toString();

        static::assertStringContainsString('first-pem', $bundle);
        static::assertStringContainsString('second-pem', $bundle);
    }
}
