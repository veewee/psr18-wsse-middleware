<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

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
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget(), WsseSignatureFixture::timestampTarget()], withTimestamp: true);

        $block = new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body(), Part::timestamp()],
        );
        $block(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));

        $this->assertTheSameConfigurationRefusesATamperedBody($block, $document);
    }

    /**
     * The insecure composition is the shorter call, so naming no parts must not mean requiring none: a peer
     * holding any trusted certificate could sign a decoy it minted in the Security header and leave the Body
     * attacker-controlled. Here only the Timestamp is signed, so the default must refuse the message.
     */
    public function test_naming_no_parts_still_requires_the_body_to_have_been_signed(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::timestampTarget()], withTimestamp: true);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
        );
    }

    public function test_naming_no_parts_accepts_a_message_whose_body_was_signed(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // The Timestamp is signed and the BinarySecurityToken is not, which is what a conformant peer emits.
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget(), WsseSignatureFixture::timestampTarget()], withTimestamp: true);

        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
        );

        // Reaching here is the pass: the block throws rather than returning a verdict.
        static::assertStringContainsString('<soap:Body', $document->toXmlString());
    }

    /**
     * Chaining to an anchor proves someone the CA vouched for signed the message, never that your service did.
     * The block therefore hands the verified signer back, so an application anchoring a CA can still compare
     * the identity it expected.
     */
    public function test_it_hands_the_verified_signer_to_the_callback(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
        $seen = null;

        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))
            ->onTrustedSigner(static function (TrustedSigner $signer) use (&$seen): void {
                $seen = $signer;
            })(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));

        static::assertInstanceOf(TrustedSigner::class, $seen);
        static::assertStringContainsString('WSSE', $seen->subjectDistinguishedName()->toString());
        static::assertSame($fixture->leafCertificate->toBase64Der(), $seen->certificate()->toBase64Der());
    }

    public function test_a_callback_that_rejects_the_signer_refuses_the_message_uniformly(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $block = (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))
            ->onTrustedSigner(static function (TrustedSigner $signer): void {
                if ($signer->subjectDistinguishedName()->toString() !== 'CN=some other service') {
                    throw new RuntimeException('unexpected peer: ' . $signer->subjectDistinguishedName()->toString());
                }
            });

        try {
            $block(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            static::fail('Expected the rejected signer to refuse the message.');
        } catch (SecurityFault $fault) {
            // The reason reaches the log, never the message a peer could read.
            static::assertSame('The inbound security header could not be processed.', $fault->getMessage());
            static::assertInstanceOf(RuntimeException::class, $fault->getPrevious());
            static::assertStringContainsString('unexpected peer', (string) $fault->getPrevious()?->getMessage());
        }
    }

    public function test_the_callback_only_runs_once_coverage_has_been_asserted(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // Only the Timestamp is signed, so the default body requirement refuses the message.
        $document = $fixture->sign([WsseSignatureFixture::timestampTarget()], withTimestamp: true);
        $ran = false;

        $block = (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))
            ->onTrustedSigner(static function (TrustedSigner $signer) use (&$ran): void {
                $ran = true;
            });

        try {
            $block(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
        } catch (SecurityFault) {
            // expected
        }

        static::assertFalse($ran);
    }

    public function test_it_verifies_a_real_ecdsa_signed_body_and_timestamp(): void
    {
        $fixture = WsseSignatureFixture::ecCaSignedLeaf();
        $document = $fixture->sign(
            [WsseSignatureFixture::bodyTarget(), WsseSignatureFixture::timestampTarget()],
            withTimestamp: true,
            signatureMethod: SignatureMethod::ECDSA_SHA256,
        );

        $block = new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body(), Part::timestamp()],
        );
        $block(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));

        $this->assertTheSameConfigurationRefusesATamperedBody($block, $document);
    }

    public function test_it_rejects_a_real_message_missing_a_required_signed_part(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::timestamp()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_rejects_a_signed_body_relocated_into_the_security_header(): void
    {
        // The XML Signature Wrapping shape the object-identity defence exists for. The genuinely signed Body is
        // moved into ds:Object inside the Security header, keeping its wsu:Id, and a forged Body takes its place
        // in the envelope. The signature still validates -- the element it covers is present and unaltered, and
        // its id still resolves -- so nothing cryptographic catches this. What catches it is that Part::body()
        // resolves to the element in the Body slot, which is not the instance the signature covered.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $dom = $document->toUnsafeDocument();
        $envelope = $dom->documentElement;
        static::assertInstanceOf(Element::class, $envelope);

        $signedBody = $dom->getElementsByTagNameNS(WsseSignatureFixture::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $signedBody);

        $security = $dom->getElementsByTagNameNS(WsseSignatureFixture::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $security);

        // A forged Body replaces the real one in the envelope, and the real one is parked under ds:Object.
        $forged = $dom->createElementNS(WsseSignatureFixture::SOAP, 'soap:Body');
        $attackerPayload = $dom->createElement('attacker');
        $attackerPayload->textContent = 'forged';
        $forged->appendChild($attackerPayload);
        $envelope->replaceChild($forged, $signedBody);

        $object = $dom->createElementNS(WsseSignatureFixture::DS, 'ds:Object');
        $object->appendChild($signedBody);
        $security->appendChild($object);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_rejects_an_untrusted_signer(): void
    {
        $fixture = WsseSignatureFixture::selfSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates(WsseSignatureFixture::caSignedLeaf()->caCertificate),
            signed: [Part::body()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_round_trips_an_inclusive_c14n_signature_when_the_policy_opts_in(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign(
            [WsseSignatureFixture::bodyTarget(), WsseSignatureFixture::timestampTarget()],
            withTimestamp: true,
            canonicalization: SignatureCanonicalization::C14N,
        );

        // The emitted CanonicalizationMethod carries the inclusive C14N 1.0 URI.
        $canonicalizationMethod = $document
            ->toUnsafeDocument()
            ->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'CanonicalizationMethod')
            ->item(0);
        static::assertInstanceOf(Element::class, $canonicalizationMethod);
        static::assertSame(
            SignatureCanonicalization::C14N->value,
            $canonicalizationMethod->getAttribute('Algorithm'),
        );

        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body(), Part::timestamp()],
        ))(new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(crypto: new CryptoPolicy(acceptedCanonicalizations: [
                SignatureCanonicalization::C14N,
                SignatureCanonicalization::EXC_C14N,
            ])),
        ));
        $this->addToAssertionCount(1);
    }

    public function test_it_rejects_an_inclusive_c14n_signature_under_the_default_policy(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign(
            [WsseSignatureFixture::bodyTarget(), WsseSignatureFixture::timestampTarget()],
            withTimestamp: true,
            canonicalization: SignatureCanonicalization::C14N,
        );

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body(), Part::timestamp()],
        ))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_it_verifies_a_signer_referenced_by_subject_key_identifier(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // The message names the signer by its Subject Key Identifier and carries no certificate; the verifier
        // must resolve it from the trust store, which holds the CA and the signer leaf.
        $document = $fixture->sign(
            [WsseSignatureFixture::bodyTarget()],
            keyIdentifier: new X509SubjectKeyIdentifier(),
        );

        $block = new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
            signed: [Part::body()],
        );
        $block(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));

        $this->assertTheSameConfigurationRefusesATamperedBody($block, $document);
    }

    /**
     * The proof an acceptance was real: tampering the signed Body must flip the very same block and document
     * to a refusal, which can only happen if the acceptance ran a genuine verification over the content.
     */
    private function assertTheSameConfigurationRefusesATamperedBody(
        VerifySignature $block,
        Document $document,
    ): void {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(WsseSignatureFixture::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);
        $body->textContent = 'tampered';

        $this->expectException(SecurityFault::class);
        $block(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }
}
