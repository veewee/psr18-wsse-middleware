<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;

final class TrustTest extends TestCase
{
    public function test_trust_store_holds_its_anchors(): void
    {
        $anchor = new Certificate('-----BEGIN CERTIFICATE-----anchor-----END CERTIFICATE-----');
        $store = TrustStore::fromCertificates($anchor);

        static::assertFalse($store->isEmpty());
        static::assertSame([$anchor], $store->anchors());
    }

    public function test_an_empty_trust_store_reports_empty(): void
    {
        static::assertTrue(TrustStore::fromCertificates()->isEmpty());
    }

    public function test_certificate_chain_exposes_leaf_first(): void
    {
        $leaf = new Certificate('-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----');
        $issuer = new Certificate('-----BEGIN CERTIFICATE-----issuer-----END CERTIFICATE-----');
        $chain = CertificateChain::fromCertificates($leaf, $issuer);

        static::assertSame($leaf, $chain->leaf());
        static::assertSame([$leaf, $issuer], $chain->all());
    }

    public function test_trusted_signer_carries_identity_and_certificate(): void
    {
        $cert = new Certificate('-----BEGIN CERTIFICATE-----leaf-----END CERTIFICATE-----');
        $signer = new TrustedSigner(DistinguishedName::fromString('CN=example,O=Acme'), $cert);

        static::assertSame('CN=example,O=Acme', $signer->subjectDistinguishedName()->toString());
        static::assertSame($cert, $signer->certificate());
    }
}
