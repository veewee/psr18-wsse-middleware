<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use SoapTest\Psr18WsseMiddleware\Unit\Clock\FrozenClock;

final class CertificateTrustTest extends TestCase
{
    public function test_a_leaf_signed_by_a_trusted_ca_is_accepted(): void
    {
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );

        static::assertStringContainsString('WSSE Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_pinned_certificate_is_accepted(): void
    {
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('pinned.crt')),
            TrustStore::fromCertificates($this->certificate('pinned.crt')),
        );

        static::assertStringContainsString('WSSE Pinned', $signer->subjectDistinguishedName()->toString());
    }

    /**
     * The store advertises pinned certificates, and pinning the peer's own certificate is the only way to say
     * "this service" rather than "anything that CA issued". A CA-issued leaf never terminates a chain at a
     * self-signed certificate inside the store, and PHP exposes no way to ask OpenSSL for a partial chain, so
     * the pin has to be honoured directly.
     */
    public function test_a_pinned_ca_issued_leaf_is_accepted_without_its_issuer(): void
    {
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('leaf.crt')),
        );

        static::assertStringContainsString('WSSE Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_pinned_leaf_does_not_make_a_sibling_from_the_same_ca_trusted(): void
    {
        $this->expectException(CertificateTrustException::class);
        $this->expectExceptionMessage('does not chain to a configured trust anchor');

        (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('pinned.crt')),
        );
    }

    /**
     * A pin is a statement about one certificate, not a licence to skip the rest of the checks: an expired or
     * signing-forbidden certificate stays refused even when it is the pin.
     */
    public function test_a_pinned_leaf_is_still_checked_for_expiry(): void
    {
        $this->expectException(CertificateTrustException::class);

        (new CertificateTrust())
            ->withClock(new FrozenClock(Timestamp::fromParts(4102444800)))
            ->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                TrustStore::fromCertificates($this->certificate('leaf.crt')),
            );
    }

    public function test_a_self_signed_certificate_not_in_the_truststore_is_rejected(): void
    {
        $this->expectException(CertificateTrustException::class);

        (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('pinned.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );
    }

    public function test_a_leaf_chaining_to_an_unknown_ca_is_rejected(): void
    {
        $this->expectException(CertificateTrustException::class);

        (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('pinned.crt')),
        );
    }

    public function test_an_expired_certificate_is_rejected(): void
    {
        // Pin the clock past any certificate's validity so the expiry check fires independently of wall time.
        $farFuture = (new CertificateTrust())->withClock(new FrozenClock(Timestamp::fromParts(253402300799)));

        $this->expectException(CertificateTrustException::class);

        $farFuture->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );
    }

    public function test_a_certificate_whose_key_usage_forbids_signing_is_rejected(): void
    {
        $this->expectException(CertificateTrustException::class);

        (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('no-signing.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );
    }

    public function test_an_empty_truststore_trusts_nothing(): void
    {
        $this->expectException(CertificateTrustException::class);

        (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates(),
        );
    }

    private function certificate(string $file): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/trust/'.$file);
    }
}
