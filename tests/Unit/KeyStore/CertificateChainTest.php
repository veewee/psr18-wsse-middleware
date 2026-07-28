<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

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

    public function test_it_orders_an_unordered_set_by_issuer_linkage(): void
    {
        // The issuer listed first. The end-entity is the certificate that issued none of the others, so
        // position must not decide it.
        $fixture = WsseSignatureFixture::caSignedLeaf();

        $chain = CertificateChain::fromUnorderedCertificates(
            $fixture->caCertificate,
            $fixture->leafCertificate,
        );

        static::assertStringContainsString('WSSE Round Trip Leaf', $chain->leaf()->info()->subject()->toString());
        static::assertNotNull($chain->intermediatesPem());
    }

    public function test_a_single_certificate_needs_no_ordering(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();

        $chain = CertificateChain::fromUnorderedCertificates($fixture->leafCertificate);

        static::assertStringContainsString('WSSE Round Trip Leaf', $chain->leaf()->info()->subject()->toString());
        static::assertNull($chain->intermediatesPem());
    }

    public function test_it_refuses_a_set_with_no_single_end_entity(): void
    {
        // Two unrelated leaves: neither issued the other, so nothing identifies which key signed.
        $one = WsseSignatureFixture::caSignedLeaf();
        $two = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(InvalidArgumentException::class);
        CertificateChain::fromUnorderedCertificates($one->leafCertificate, $two->leafCertificate);
    }

    public function test_it_refuses_an_empty_set(): void
    {
        $this->expectException(InvalidArgumentException::class);
        CertificateChain::fromUnorderedCertificates();
    }
}
