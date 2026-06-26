<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\Resolver;

final class ResolverTest extends TestCase
{
    public function test_it_returns_a_trusted_signer_for_a_chaining_certificate(): void
    {
        $signer = (new Resolver(new CertificateTrust()))->verifyTrust(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );

        static::assertStringContainsString('WSSE Leaf', $signer->subjectDistinguishedName());
    }

    public function test_it_propagates_the_trust_failure_for_an_untrusted_certificate(): void
    {
        $this->expectException(CertificateTrustException::class);

        (new Resolver(new CertificateTrust()))->verifyTrust(
            CertificateChain::fromCertificates($this->certificate('pinned.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );
    }

    private function certificate(string $file): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/trust/'.$file);
    }
}
