<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\DigestVerifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\ResolvedVerificationReference;
use VeeWee\Xml\Dom\Document;

#[RequiresPhp('>= 8.4.21')]
final class DigestVerifierTest extends TestCase
{
    public function test_it_accepts_a_matching_digest(): void
    {
        $element = $this->element();
        $expected = $this->expectedDigest($element);

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertTrue($verifier->verify(
            new ResolvedVerificationReference($element, DigestMethod::SHA256, $expected, SignatureCanonicalization::EXC_C14N, []),
        ));
    }

    public function test_it_rejects_a_tampered_element(): void
    {
        $element = $this->element();
        $expected = $this->expectedDigest($element);

        // Flip the element content after computing the expected digest.
        $element->textContent = 'tampered';

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        static::assertFalse($verifier->verify(
            new ResolvedVerificationReference($element, DigestMethod::SHA256, $expected, SignatureCanonicalization::EXC_C14N, []),
        ));
    }

    public function test_it_rejects_a_malformed_expected_digest_value(): void
    {
        $element = $this->element();

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());

        $this->expectException(SignatureVerificationFailed::class);
        $verifier->verify(
            new ResolvedVerificationReference($element, DigestMethod::SHA256, 'not valid base64 !!!', SignatureCanonicalization::EXC_C14N, []),
        );
    }

    public function test_it_propagates_a_canonicalization_failure(): void
    {
        $element = $this->element();

        $canonicalizer = new class implements Canonicalizer {
            public function canonicalize($node, $method, ?array $inclusivePrefixes = null): string
            {
                throw CanonicalizationFailed::unsupportedAlgorithm($method);
            }
        };

        $verifier = new DigestVerifier($canonicalizer, new Digest());

        $this->expectException(CanonicalizationFailed::class);
        $verifier->verify(
            new ResolvedVerificationReference($element, DigestMethod::SHA256, base64_encode('x'), SignatureCanonicalization::EXC_C14N, []),
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
