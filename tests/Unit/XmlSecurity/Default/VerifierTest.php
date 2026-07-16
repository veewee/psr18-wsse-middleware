<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Default;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\CertificateExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Resolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignatureLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignatureValidator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfoParser;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * The strong proof of B4: it round-trips against the B3 signer, rejects the XML-signature-wrapping and trust
 * attacks, and surfaces every failure through the single uniform exception so it cannot be used as an oracle.
 */
#[RequiresPhp('>= 8.4.21')]
final class VerifierTest extends TestCase
{
    public function test_it_verifies_a_b3_signed_body_and_reports_the_signed_element(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate));

        static::assertInstanceOf(VerifiedSignature::class, $result);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertStringContainsString('WSSE Round Trip Leaf', $result->signer->subjectDistinguishedName()->toString());
    }

    /**
     * @return iterable<string, array{0: SignatureMethod, 1: DigestMethod}>
     */
    public static function algorithmProvider(): iterable
    {
        yield 'rsa-sha256' => [SignatureMethod::RSA_SHA256, DigestMethod::SHA256];
        yield 'rsa-sha384' => [SignatureMethod::RSA_SHA384, DigestMethod::SHA384];
        yield 'rsa-sha512' => [SignatureMethod::RSA_SHA512, DigestMethod::SHA512];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('algorithmProvider')]
    public function test_it_verifies_each_accepted_rsa_algorithm(
        SignatureMethod $signatureMethod,
        DigestMethod $digestMethod,
    ): void {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()], signatureMethod: $signatureMethod, digestMethod: $digestMethod);

        $result = $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            acceptedSignatureMethods: [$signatureMethod],
            acceptedDigestMethods: [$digestMethod],
            acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
        ));

        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
    }

    public function test_it_accepts_a_legacy_rsa_sha1_signature_only_when_the_policy_allows_it(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign(
            [WsseSignatureFixture::bodyTarget()],
            signatureMethod: SignatureMethod::RSA_SHA1,
            digestMethod: DigestMethod::SHA1,
        );

        $result = $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA1],
            acceptedDigestMethods: [DigestMethod::SHA1],
            acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
        ));

        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
    }

    public function test_it_verifies_a_signed_timestamp(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::timestampTarget()], withTimestamp: true);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate));

        static::assertTrue($result->signedElements->wasSigned($this->timestamp($document)));
    }

    public function test_it_verifies_the_body_and_the_timestamp_together(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget(), WsseSignatureFixture::timestampTarget()], withTimestamp: true);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate));

        static::assertCount(2, $result->signedElements->signedIds());
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertTrue($result->signedElements->wasSigned($this->timestamp($document)));
    }

    public function test_was_signed_uses_object_identity_not_structural_equality(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate));

        // A structurally identical clone is a different object, so it is not the signed instance.
        $clone = $this->body($document)->cloneNode(true);
        static::assertInstanceOf(Element::class, $clone);
        static::assertNotSame($this->body($document), $clone);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertFalse($result->signedElements->wasSigned($clone));
    }

    public function test_it_rejects_a_tampered_body(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $body = $this->body($document);
        $injected = $document->toUnsafeDocument()->createElement('injected');
        $injected->textContent = 'tampered';
        $body->appendChild($injected);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate));
    }

    public function test_it_rejects_a_tampered_signature_value(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $signatureValue = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'SignatureValue')->item(0);
        static::assertInstanceOf(Element::class, $signatureValue);
        $signatureValue->textContent = base64_encode('forged-signature-bytes-that-will-not-verify');

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate));
    }

    public function test_it_rejects_a_reference_with_a_duplicate_digest_method(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $native = $document->toUnsafeDocument();
        $reference = $native->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Reference')->item(0);
        static::assertInstanceOf(Element::class, $reference);
        $duplicate = $native->createElementNS(WsseSignatureFixture::DS, 'ds:DigestMethod');
        $duplicate->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $reference->appendChild($duplicate);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate));
    }

    public function test_it_rejects_a_self_signed_signer_not_in_the_trust_store(): void
    {
        $fixture = WsseSignatureFixture::selfSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        // Anchor the trust store to a different CA, so the self-signed signer does not chain.
        $other = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($other->caCertificate));
    }

    public function test_it_rejects_a_signer_chaining_to_an_unknown_ca(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $unknown = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($unknown->caCertificate));
    }

    public function test_it_rejects_an_empty_trust_store(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates(),
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
            acceptedDigestMethods: [DigestMethod::SHA256],
            acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
        ));
    }

    public function test_it_rejects_a_signature_method_not_in_the_allow_list(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            // The message is RSA-SHA256; the policy only accepts RSA-SHA512.
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA512],
            acceptedDigestMethods: [DigestMethod::SHA256],
            acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
        ));
    }

    public function test_it_rejects_a_digest_method_not_in_the_allow_list(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
            acceptedDigestMethods: [DigestMethod::SHA512],
            acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
        ));
    }

    public function test_it_rejects_an_unknown_signature_method_uri(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
        $this->rewriteAttribute($document, WsseSignatureFixture::DS, 'SignatureMethod', 'Algorithm', 'urn:made-up');

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate));
    }

    public function test_it_rejects_a_missing_signature(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'">'
            .'<soap:Header><wsse:Security/></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body></soap:Envelope>'
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy(WsseSignatureFixture::caSignedLeaf()->caCertificate));
    }

    public function test_it_rejects_more_than_one_signature(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $security = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $security);
        $signature = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);
        $security->appendChild($signature->cloneNode(true));

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate));
    }

    public function test_a_relocated_signed_element_is_resolved_by_id_so_a_wrapper_copy_is_not_signed(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $dom = $document->toUnsafeDocument();
        $body = $this->body($document);
        $signedId = $body->getAttributeNS(WsseSignatureFixture::WSU, 'Id');

        // Relocate a structurally identical copy of the signed Body into a wrapper elsewhere in the message,
        // carrying a different id. The original signed Body is left untouched.
        $header = $dom->getElementsByTagNameNS(WsseSignatureFixture::SOAP, 'Header')->item(0);
        static::assertInstanceOf(Element::class, $header);
        $wrapper = $dom->createElement('wrapper');
        $copy = $body->cloneNode(true);
        static::assertInstanceOf(Element::class, $copy);
        $copy->setAttributeNS(WsseSignatureFixture::WSU, 'wsu:Id', 'wrapped-copy');
        $wrapper->appendChild($copy);
        $header->appendChild($wrapper);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate));

        // The original id still resolves to the original element, and the wrapper copy was never signed.
        static::assertContains($signedId, $result->signedElements->signedIds());
        static::assertFalse($result->signedElements->wasSigned($copy));
    }

    public function test_a_duplicate_wsu_id_is_rejected(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $dom = $document->toUnsafeDocument();
        $body = $this->body($document);
        $signedId = $body->getAttributeNS(WsseSignatureFixture::WSU, 'Id');

        // A second element claiming the signed id makes the reference ambiguous.
        $twin = $dom->createElement('twin');
        $twin->setAttributeNS(WsseSignatureFixture::WSU, 'wsu:Id', $signedId);
        $body->appendChild($twin);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate));
    }

    /**
     * Every failure path raises the same exception type, so a caller cannot tell which check failed.
     */
    public function test_all_failure_modes_share_one_exception_type(): void
    {
        $thrown = [];

        $cases = [
            'missing signature' => function (): void {
                $document = Document::fromXmlString(
                    '<soap:Envelope xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
                    .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'">'
                    .'<soap:Header><wsse:Security/></soap:Header><soap:Body/></soap:Envelope>'
                );
                $this->verifier()->verify($document, $this->policy(WsseSignatureFixture::caSignedLeaf()->caCertificate));
            },
            'untrusted signer' => function (): void {
                $fixture = WsseSignatureFixture::caSignedLeaf();
                $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
                $this->verifier()->verify($document, $this->policy(WsseSignatureFixture::caSignedLeaf()->caCertificate));
            },
            'tampered body' => function (): void {
                $fixture = WsseSignatureFixture::caSignedLeaf();
                $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
                $this->body($document)->setAttribute('tampered', 'yes');
                $this->verifier()->verify($document, $this->policy($fixture->caCertificate));
            },
            'disallowed algorithm' => function (): void {
                $fixture = WsseSignatureFixture::caSignedLeaf();
                $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
                $this->verifier()->verify($document, new VerificationPolicy(
                    trustStore: TrustStore::fromCertificates($fixture->caCertificate),
                    acceptedSignatureMethods: [SignatureMethod::RSA_SHA512],
                    acceptedDigestMethods: [DigestMethod::SHA256],
                    acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
                ));
            },
        ];

        foreach ($cases as $name => $case) {
            try {
                $case();
                static::fail(sprintf('Case "%s" did not fail.', $name));
            } catch (Throwable $exception) {
                $thrown[$name] = $exception::class;
            }
        }

        static::assertSame(
            array_fill_keys(array_keys($cases), SignatureVerificationFailed::class),
            $thrown,
        );
    }

    private function policy(Certificate $anchor): VerificationPolicy
    {
        return new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($anchor),
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
            acceptedDigestMethods: [DigestMethod::SHA256],
            acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
        );
    }

    private function verifier(): Verifier
    {
        $canonicalizer = new DomCanonicalizer();

        return new Verifier(
            new SignatureLocator(),
            new SignedInfoParser(),
            new AlgorithmPolicyEnforcer(),
            new CertificateExtractor(),
            new ReferenceResolver(),
            new DigestVerifier($canonicalizer, new Digest()),
            new SignatureValidator($canonicalizer, new OpenSslSigner()),
            new Resolver(new CertificateTrust()),
        );
    }

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(WsseSignatureFixture::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }

    private function timestamp(Document $document): Element
    {
        $timestamp = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::WSU, 'Timestamp')->item(0);
        static::assertInstanceOf(Element::class, $timestamp);

        return $timestamp;
    }

    private function rewriteAttribute(
        Document $document,
        string $namespace,
        string $localName,
        string $attribute,
        string $value,
    ): void {
        $element = $document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName)->item(0);
        static::assertInstanceOf(Element::class, $element);
        $element->setAttribute($attribute, $value);
    }
}
