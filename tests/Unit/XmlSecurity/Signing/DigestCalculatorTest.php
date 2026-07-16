<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Signing;

use Dom\Element;
use Dom\Node;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ResolvedReference;
use VeeWee\Xml\Dom\Document;

final class DigestCalculatorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';

    #[RequiresPhp('>= 8.4.21')]
    public function test_it_produces_the_expected_base64_digest(): void
    {
        $reference = $this->reference();
        $calculator = new DigestCalculator(new DomCanonicalizer(), new Digest());

        $result = $calculator->calculate($reference, SignatureCanonicalization::EXC_C14N, DigestMethod::SHA256);

        $expected = base64_encode(hash('sha256', $reference->element->C14N(true, false), true));
        static::assertSame($expected, $result->digestValueBase64);
        static::assertSame('Body-1', $result->id);
    }

    public function test_it_propagates_a_canonicalization_failure(): void
    {
        $canonicalizer = new class implements Canonicalizer {
            public function canonicalize(Node $node, SignatureCanonicalization $method, ?array $inclusivePrefixes = null): string
            {
                throw CanonicalizationFailed::nativeError($node, $method);
            }
        };

        $this->expectException(CanonicalizationFailed::class);
        (new DigestCalculator($canonicalizer, new Digest()))
            ->calculate($this->reference(), SignatureCanonicalization::EXC_C14N, DigestMethod::SHA256);
    }

    public function test_it_carries_the_requested_digest_method(): void
    {
        $canonicalizer = new class implements Canonicalizer {
            public function canonicalize(Node $node, SignatureCanonicalization $method, ?array $inclusivePrefixes = null): string
            {
                return 'canonical-bytes';
            }
        };

        $result = (new DigestCalculator($canonicalizer, new Digest()))
            ->calculate($this->reference(), SignatureCanonicalization::EXC_C14N, DigestMethod::SHA512);

        static::assertSame(DigestMethod::SHA512, $result->digestMethod);
    }

    private function reference(): ResolvedReference
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body wsu:Id="Body-1" xmlns:wsu="urn:wsu"><data>x</data></soap:Body></soap:Envelope>'
        );
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return new ResolvedReference($body, 'Body-1');
    }
}
