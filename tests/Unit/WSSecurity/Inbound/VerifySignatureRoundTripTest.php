<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateFieldExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\WsseSignatureFixture;

/**
 * The strong proof of the inbound VerifySignature block through the real verifier: a genuinely signed Body and
 * Timestamp pass, a missing required signed part is refused, and an untrusted signer is refused. Every failure
 * surfaces as one uniform SecurityFault so the block is never a forgery oracle.
 */
#[RequiresPhp('>= 8.4.21')]
final class VerifySignatureRoundTripTest extends TestCase
{
    public function test_it_verifies_a_real_signed_body_and_timestamp(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([Part::body(), Part::timestamp()], withTimestamp: true);

        $this->expectNotToPerformAssertions();
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body(), Part::timestamp()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_verifies_a_real_ecdsa_signed_body_and_timestamp(): void
    {
        $fixture = WsseSignatureFixture::ecCaSignedLeaf();
        $document = $fixture->sign(
            [Part::body(), Part::timestamp()],
            withTimestamp: true,
            signatureMethod: SignatureMethod::ECDSA_SHA256,
        );

        $this->expectNotToPerformAssertions();
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body(), Part::timestamp()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_rejects_a_real_message_missing_a_required_signed_part(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([Part::body()]);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::timestamp()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_rejects_an_untrusted_signer(): void
    {
        $fixture = WsseSignatureFixture::selfSignedLeaf();
        $document = $fixture->sign([Part::body()]);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates(WsseSignatureFixture::caSignedLeaf()->caCertificate),
            signed: [Part::body()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_verifies_a_signer_referenced_by_subject_key_identifier(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // The message names the signer by its Subject Key Identifier and carries no certificate; the verifier
        // must resolve it from the trust store, which holds the CA and the signer leaf.
        $document = $fixture->sign(
            [Part::body()],
            keyIdentifier: new X509SubjectKeyIdentifier(new CertificateFieldExtractor()),
        );

        $this->expectNotToPerformAssertions();
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
            signed: [Part::body()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }
}
