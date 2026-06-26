<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Internal\Validator\RequiredPartsValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\CertificateExtractor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\DigestVerifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\PartLocator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\ReferenceResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\Resolver;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\SignatureValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\Verifier;
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
            $this->verifier(),
            TrustStore::fromCertificates($fixture->caCertificate),
            new RequiredPartsValidator(new PartLocator()),
            signed: [Part::body(), Part::timestamp()],
        ))(new WsseContext($document, SoapVersion::Soap12));
    }

    public function test_it_rejects_a_real_message_missing_a_required_signed_part(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([Part::body()]);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            $this->verifier(),
            TrustStore::fromCertificates($fixture->caCertificate),
            new RequiredPartsValidator(new PartLocator()),
            signed: [Part::timestamp()],
        ))(new WsseContext($document, SoapVersion::Soap12));
    }

    public function test_it_rejects_an_untrusted_signer(): void
    {
        $fixture = WsseSignatureFixture::selfSignedLeaf();
        $document = $fixture->sign([Part::body()]);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            $this->verifier(),
            TrustStore::fromCertificates(WsseSignatureFixture::caSignedLeaf()->caCertificate),
            new RequiredPartsValidator(new PartLocator()),
            signed: [Part::body()],
        ))(new WsseContext($document, SoapVersion::Soap12));
    }

    private function verifier(): Verifier
    {
        $canonicalizer = new DomCanonicalizer();

        return new Verifier(
            new CertificateExtractor(),
            new ReferenceResolver(),
            new DigestVerifier($canonicalizer, new Digest()),
            new SignatureValidator($canonicalizer, new OpenSslSigner()),
            new Resolver(new CertificateTrust()),
        );
    }
}
