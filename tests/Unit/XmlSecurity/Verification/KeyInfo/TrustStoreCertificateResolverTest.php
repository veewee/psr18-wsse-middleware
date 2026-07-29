<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\KeyInfo;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\KeyIdentifierKind;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\TrustStoreCertificateResolver;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;

/**
 * Covers the trust-store matching policy in isolation: a typed certificate reference resolves to the single
 * matching anchor, an unknown identifier is refused, and two anchors carrying the same identifier make the
 * reference ambiguous. The match is by computed identifier, so no anchor is ever silently preferred.
 *
 * A reference naming an identifier this library does not support is not covered here, because it cannot be
 * built: the reference carries a KeyIdentifierKind, so an unknown spelling is refused while ds:KeyInfo is read.
 * CertificateExtractorTest pins that from the document instead.
 */
final class TrustStoreCertificateResolverTest extends TestCase
{
    public function test_it_resolves_a_unique_subject_key_identifier_match(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $reference = CertificateReference::keyIdentifier(
            KeyIdentifierKind::SubjectKeyIdentifier,
            $fixture->leafCertificate->info()->subjectKeyIdentifier()->toBase64(),
        );

        $resolved = (new TrustStoreCertificateResolver())->resolve(
            $reference,
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($fixture->leafCertificate, $resolved);
    }

    public function test_it_resolves_a_unique_thumbprint_match(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $reference = CertificateReference::keyIdentifier(
            KeyIdentifierKind::ThumbprintSha1,
            $fixture->leafCertificate->info()->thumbprintSha1()->toBase64(),
        );

        $resolved = (new TrustStoreCertificateResolver())->resolve(
            $reference,
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($fixture->leafCertificate, $resolved);
    }

    public function test_it_resolves_a_unique_issuer_serial_match(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $issuerSerial = $fixture->leafCertificate->info()->issuerSerial();
        $reference = CertificateReference::issuerSerial($issuerSerial->issuer->toString(), $issuerSerial->serialNumber->toString());

        $other = WsseSignatureFixture::selfSignedLeaf();

        $resolved = (new TrustStoreCertificateResolver())->resolve(
            $reference,
            TrustStore::fromCertificates($other->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($fixture->leafCertificate, $resolved);
    }

    public function test_it_refuses_an_identifier_no_anchor_carries(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $reference = CertificateReference::keyIdentifier(
            KeyIdentifierKind::SubjectKeyIdentifier,
            $fixture->leafCertificate->info()->subjectKeyIdentifier()->toBase64(),
        );

        // The trust store holds only the CA, not the signer leaf the identifier names.
        $this->expectException(SignatureVerificationFailed::class);
        (new TrustStoreCertificateResolver())->resolve(
            $reference,
            TrustStore::fromCertificates($fixture->caCertificate),
        );
    }

    public function test_it_refuses_an_ambiguous_match(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $reference = CertificateReference::keyIdentifier(
            KeyIdentifierKind::SubjectKeyIdentifier,
            $fixture->leafCertificate->info()->subjectKeyIdentifier()->toBase64(),
        );

        // Two anchors carrying the same identifier make the reference ambiguous.
        $this->expectException(SignatureVerificationFailed::class);
        (new TrustStoreCertificateResolver())->resolve(
            $reference,
            TrustStore::fromCertificates($fixture->leafCertificate, $fixture->leafCertificate),
        );
    }


    public function test_it_refuses_a_carried_reference_it_cannot_resolve(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $reference = CertificateReference::carried('does-not-matter');

        $this->expectException(SignatureVerificationFailed::class);
        (new TrustStoreCertificateResolver())->resolve(
            $reference,
            TrustStore::fromCertificates($fixture->leafCertificate),
        );
    }
}
