<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;

final class CertificateChainTest extends TestCase
{
    public function test_a_leaf_only_chain_has_no_intermediates(): void
    {
        $chain = CertificateChain::fromCertificates(new Certificate('leaf-pem'));

        static::assertNull($chain->intermediatesPem());
    }

    public function test_it_concatenates_the_certificates_above_the_leaf(): void
    {
        $chain = CertificateChain::fromCertificates(
            new Certificate('leaf-pem'),
            new Certificate('intermediate-pem'),
            new Certificate('root-pem'),
        );

        $intermediates = (string) $chain->intermediatesPem()?->toString();

        static::assertStringContainsString('intermediate-pem', $intermediates);
        static::assertStringContainsString('root-pem', $intermediates);
        static::assertStringNotContainsString('leaf-pem', $intermediates);
    }
}
