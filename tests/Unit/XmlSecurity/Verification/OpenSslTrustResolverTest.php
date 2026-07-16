<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\OpenSslTrustResolver;

final class OpenSslTrustResolverTest extends TestCase
{
    public function test_it_returns_a_trusted_signer_for_a_chaining_certificate(): void
    {
        $signer = (new OpenSslTrustResolver(new CertificateTrust()))->verifyTrust(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );

        static::assertStringContainsString('WSSE Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_it_propagates_the_trust_failure_for_an_untrusted_certificate(): void
    {
        $this->expectException(CertificateTrustException::class);

        (new OpenSslTrustResolver(new CertificateTrust()))->verifyTrust(
            CertificateChain::fromCertificates($this->certificate('pinned.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );
    }

    private function certificate(string $file): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/trust/'.$file);
    }
}
