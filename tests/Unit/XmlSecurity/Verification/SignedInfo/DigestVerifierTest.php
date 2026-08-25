<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ParsedReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ResolvedExternalReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ResolvedVerificationReference;
use VeeWee\Xml\Dom\Document;

final class DigestVerifierTest extends TestCase
{
    private const SWA_CONTENT = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';

    public function test_it_accepts_an_external_part_whose_octets_match(): void
    {
        $bytes = '%PDF-1.7 raw';
        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertTrue($verifier->verifyExternalPart(
            $this->externalReference($bytes, base64_encode(hash('sha256', $bytes, true))),
        ));
    }

    public function test_it_rejects_an_external_part_whose_octets_differ(): void
    {
        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertFalse($verifier->verifyExternalPart(
            $this->externalReference('tampered', base64_encode(hash('sha256', '%PDF-1.7 raw', true))),
        ));
    }

    public function test_it_digests_an_external_part_from_the_start_even_when_read_before(): void
    {
        $bytes = '%PDF-1.7 raw';
        $reference = $this->externalReference($bytes, base64_encode(hash('sha256', $bytes, true)));

        // A spent stream must not silently digest as nothing: the same part is read more than once per
        // message, once while decrypting and again here.
        $reference->part->content->getContents();

        static::assertTrue((new DigestVerifier(new DomCanonicalizer(), new Digest()))
            ->verifyExternalPart($reference));
    }

    public function test_it_refuses_an_external_digest_value_that_is_not_base64(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('The digest value is not valid base64.');

        (new DigestVerifier(new DomCanonicalizer(), new Digest()))
            ->verifyExternalPart($this->externalReference('x', 'not!base64'));
    }

    private function externalReference(string $bytes, string $expectedBase64): ResolvedExternalReference
    {
        return new ResolvedExternalReference(
            new ParsedReference(DigestMethod::SHA256, $expectedBase64, null, [], self::SWA_CONTENT),
            new ExternalPart(
                'cid:invoice@example.com',
                'application/pdf',
                MemoryStream::create()->write($bytes)->rewind(),
            ),
        );
    }

    #[RequiresPhp('>= 8.4.21')]
    public function test_it_accepts_a_matching_digest(): void
    {
        $element = $this->element();
        $expected = $this->expectedDigest($element);

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertTrue($verifier->verify(
            new ResolvedVerificationReference(new ParsedReference(DigestMethod::SHA256, $expected, SignatureCanonicalization::EXC_C14N, []), $element, 'ref-1'),
        ));
    }

    #[RequiresPhp('>= 8.4.21')]
    public function test_an_enveloped_reference_digests_the_element_without_its_signature(): void
    {
        // The whole point of the enveloped-signature transform: the digest covers the element minus the
        // signature inside it. If the signature were included, no such signature could ever verify, because its
        // own value cannot be known while it is being computed.
        [$assertion, $signature] = $this->envelopedAssertion();
        $expected = $this->digestOf($assertion, $signature);

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertTrue($verifier->verify(new ResolvedVerificationReference(
            new ParsedReference(DigestMethod::SHA256, $expected, SignatureCanonicalization::EXC_C14N, []),
            $assertion,
            'Assertion',
            $signature,
        )));
    }

    #[RequiresPhp('>= 8.4.21')]
    public function test_an_enveloped_reference_still_covers_everything_outside_the_signature(): void
    {
        // Excluding the signature must not turn into excluding the payload: tampering with content beside the
        // signature has to break the digest, or the transform would be a hole rather than a rule.
        [$assertion, $signature] = $this->envelopedAssertion();
        $expected = $this->digestOf($assertion, $signature);

        $payload = $assertion->firstElementChild;
        static::assertInstanceOf(Element::class, $payload);
        $payload->textContent = 'tampered';

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertFalse($verifier->verify(new ResolvedVerificationReference(
            new ParsedReference(DigestMethod::SHA256, $expected, SignatureCanonicalization::EXC_C14N, []),
            $assertion,
            'Assertion',
            $signature,
        )));
    }

    #[RequiresPhp('>= 8.4.21')]
    public function test_a_digest_taken_with_the_signature_included_does_not_verify_as_enveloped(): void
    {
        // Proves the exclusion is actually applied rather than silently ignored: the two canonical forms differ,
        // so a digest over the signature-inclusive form must not satisfy an enveloped reference.
        [$assertion, $signature] = $this->envelopedAssertion();
        $inclusive = base64_encode((new Digest())->hash(
            (new DomCanonicalizer())->canonicalize($assertion, SignatureCanonicalization::EXC_C14N),
            DigestMethod::SHA256,
        ));

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertFalse($verifier->verify(new ResolvedVerificationReference(
            new ParsedReference(DigestMethod::SHA256, $inclusive, SignatureCanonicalization::EXC_C14N, []),
            $assertion,
            'Assertion',
            $signature,
        )));
    }

    /**
     * An assertion holding its own signature, plus that signature.
     *
     * @return array{0: Element, 1: Element}
     */
    private function envelopedAssertion(): array
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            .' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><soap:Header>'
            .'<a:Assertion xmlns:a="urn:assertion" ID="Assertion"><a:Payload>signed</a:Payload>'
            .'<ds:Signature><ds:SignedInfo>inner</ds:SignedInfo></ds:Signature>'
            .'</a:Assertion></soap:Header><soap:Body/></soap:Envelope>'
        );

        $unsafe = $document->toUnsafeDocument();
        $assertion = $unsafe->getElementsByTagNameNS('urn:assertion', 'Assertion')->item(0);
        $signature = $unsafe->getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $assertion);
        static::assertInstanceOf(Element::class, $signature);

        return [$assertion, $signature];
    }

    private function digestOf(Element $element, Element $withoutSubtree): string
    {
        return base64_encode((new Digest())->hash(
            (new DomCanonicalizer())->canonicalize($element, SignatureCanonicalization::EXC_C14N, null, $withoutSubtree),
            DigestMethod::SHA256,
        ));
    }

    #[RequiresPhp('>= 8.4.21')]
    public function test_it_rejects_a_tampered_element(): void
    {
        $element = $this->element();
        $expected = $this->expectedDigest($element);

        // Flip the element content after computing the expected digest.
        $element->textContent = 'tampered';

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertFalse($verifier->verify(
            new ResolvedVerificationReference(new ParsedReference(DigestMethod::SHA256, $expected, SignatureCanonicalization::EXC_C14N, []), $element, 'ref-1'),
        ));
    }

    public function test_it_rejects_a_malformed_expected_digest_value(): void
    {
        $element = $this->element();

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        $this->expectException(SignatureVerificationFailed::class);
        $verifier->verify(
            new ResolvedVerificationReference(new ParsedReference(DigestMethod::SHA256, 'not valid base64 !!!', SignatureCanonicalization::EXC_C14N, []), $element, 'ref-1'),
        );
    }

    public function test_it_propagates_a_canonicalization_failure(): void
    {
        $element = $this->element();

        $canonicalizer = new class implements Canonicalizer {
            public function canonicalize($node, $method, ?array $inclusivePrefixes = null, $withoutSubtree = null): string
            {
                throw CanonicalizationFailed::nativeError($node, $method);
            }
        };

        $verifier = new DigestVerifier($canonicalizer, new Digest());

        $this->expectException(CanonicalizationFailed::class);
        $verifier->verify(
            new ResolvedVerificationReference(new ParsedReference(DigestMethod::SHA256, base64_encode('x'), SignatureCanonicalization::EXC_C14N, []), $element, 'ref-1'),
        );
    }

    private function element(): Element
    {
        $document = Document::fromXmlString('<root><payload>hello</payload></root>');
        $element = $document->toUnsafeDocument()->getElementsByTagName('payload')->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }

    private function expectedDigest(Element $element): string
    {
        $canonical = (new DomCanonicalizer())->canonicalize($element, SignatureCanonicalization::EXC_C14N);

        return base64_encode((new Digest())->hash($canonical, DigestMethod::SHA256));
    }
}
