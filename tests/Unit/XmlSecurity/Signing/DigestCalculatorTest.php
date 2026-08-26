<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Signing;

use Dom\Element;
use Dom\Node;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ResolvedReference;
use VeeWee\Xml\Dom\Document;

final class DigestCalculatorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const SWA_CONTENT = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';

    #[RequiresPhp('>= 8.4.21')]
    public function test_it_produces_the_expected_base64_digest(): void
    {
        $reference = $this->reference();
        $calculator = new DigestCalculator(new DomCanonicalizer(), new Digest());

        $result = $calculator->forElement($reference, SignatureCanonicalization::EXC_C14N, DigestMethod::SHA256);

        $expected = base64_encode(hash('sha256', $reference->element->C14N(true, false), true));
        static::assertSame($expected, $result->digestValueBase64);
        static::assertSame('#Body-1', $result->uri);
    }

    public function test_an_element_reference_declares_the_canonicalization_it_was_digested_under(): void
    {
        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forElement($this->reference(), SignatureCanonicalization::EXC_C14N, DigestMethod::SHA256, ['soap']);

        static::assertCount(1, $result->transforms);
        static::assertSame(SignatureCanonicalization::EXC_C14N->value, $result->transforms[0]->algorithm);
        static::assertSame(['soap'], $result->transforms[0]->inclusivePrefixes);
    }

    public function test_an_inclusive_canonicalization_pins_no_prefixes(): void
    {
        // A PrefixList parameterizes exclusive C14N only. Inclusive C14N already emits every declaration in
        // scope, so a reference declaring one would describe a canonicalization that never ran.
        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forElement($this->reference(), SignatureCanonicalization::C14N, DigestMethod::SHA256, ['soap']);

        static::assertSame([], $result->transforms[0]->inclusivePrefixes);
    }

    public function test_it_propagates_a_canonicalization_failure(): void
    {
        $canonicalizer = new class implements Canonicalizer {
            public function canonicalize(Node $node, SignatureCanonicalization $method, ?array $inclusivePrefixes = null, ?Element $withoutSubtree = null): string
            {
                throw CanonicalizationFailed::nativeError($node, $method);
            }
        };

        $this->expectException(CanonicalizationFailed::class);
        (new DigestCalculator($canonicalizer, new Digest()))
            ->forElement($this->reference(), SignatureCanonicalization::EXC_C14N, DigestMethod::SHA256);
    }

    public function test_it_carries_the_requested_digest_method(): void
    {
        $canonicalizer = new class implements Canonicalizer {
            public function canonicalize(Node $node, SignatureCanonicalization $method, ?array $inclusivePrefixes = null, ?Element $withoutSubtree = null): string
            {
                return 'canonical-bytes';
            }
        };

        $result = (new DigestCalculator($canonicalizer, new Digest()))
            ->forElement($this->reference(), SignatureCanonicalization::EXC_C14N, DigestMethod::SHA512);

        static::assertSame(DigestMethod::SHA512, $result->digestMethod);
    }

    public function test_an_external_part_is_digested_over_its_octets_with_no_canonicalization(): void
    {
        $part = new ExternalPart('cid:invoice@example.com', 'application/pdf', $this->stream('%PDF-1.7 raw'));

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);

        static::assertSame(base64_encode(hash('sha256', '%PDF-1.7 raw', true)), $result->digestValueBase64);
    }

    public function test_an_external_part_reference_points_at_the_part_verbatim(): void
    {
        $part = new ExternalPart('cid:invoice@example.com', 'application/pdf', $this->stream('x'));

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);

        // No '#'. Binding the digest to this exact cid is what makes swapping two parts a mismatch rather
        // than a silent substitution.
        static::assertSame('cid:invoice@example.com', $result->uri);
        static::assertCount(1, $result->transforms);
        static::assertSame(self::SWA_CONTENT, $result->transforms[0]->algorithm);
        static::assertSame([], $result->transforms[0]->inclusivePrefixes);
    }

    public function test_it_digests_an_external_part_from_the_start_even_when_read_before(): void
    {
        $stream = $this->stream('%PDF-1.7 raw');
        $stream->getContents();

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))->forExternalPart(
            new ExternalPart('cid:invoice@example.com', 'application/pdf', $stream),
            DigestMethod::SHA256,
            self::SWA_CONTENT,
        );

        static::assertSame(base64_encode(hash('sha256', '%PDF-1.7 raw', true)), $result->digestValueBase64);
    }

    public function test_it_digests_a_text_part_with_its_line_endings_normalised(): void
    {
        // The transform normalizes line endings in text content before digesting, so the digest is over the
        // normalized form rather than over the octets. A peer applying the same rule reproduces it.
        $part = new ExternalPart('cid:note@example.com', 'text/plain', $this->stream("one\ntwo\r\nthree\rfour"));

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);

        static::assertSame(
            base64_encode(hash('sha256', "one\r\ntwo\r\nthree\r\nfour", true)),
            $result->digestValueBase64,
        );
    }

    public function test_it_normalises_any_text_subtype(): void
    {
        $part = new ExternalPart('cid:page@example.com', 'text/html; charset=utf-8', $this->stream("<p>\nx</p>"));

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);

        static::assertSame(
            base64_encode(hash('sha256', "<p>\r\nx</p>", true)),
            $result->digestValueBase64,
        );
    }

    public function test_it_leaves_a_binary_part_alone_even_when_it_holds_line_endings(): void
    {
        // Only text is normalized. Rewriting a byte inside a binary part would digest something the file is
        // not, and a peer digesting it verbatim would disagree.
        $part = new ExternalPart('cid:file@example.com', 'application/pdf', $this->stream("a\nb\rc"));

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);

        static::assertSame(base64_encode(hash('sha256', "a\nb\rc", true)), $result->digestValueBase64);
    }

    #[DataProvider('xmlMediaTypes')]
    public function test_it_digests_an_xml_part_over_its_canonical_form(string $mimeType): void
    {
        // Exclusive C14N first, so the digest is over the canonical form rather than the octets: whitespace
        // between attributes and a self-closing tag are two spellings of the same tree, and a peer digests
        // the one form both sides can compute.
        $part = new ExternalPart('cid:doc@example.com', $mimeType, $this->stream('<a  b="1"/>'));

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);

        static::assertSame(
            base64_encode(hash('sha256', '<a b="1"></a>', true)),
            $result->digestValueBase64,
        );
    }

    public function test_it_refuses_a_part_that_reads_zero_bytes(): void
    {
        // The same reason the sealer refuses one: the caller ships an empty file believing it was protected,
        // and a stream that cannot rewind reads this way too. A signature over nothing is still a valid
        // signature, so nothing downstream notices.
        $part = new ExternalPart('cid:empty@example.com', 'application/pdf', $this->stream(''));

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage('The external part "cid:empty@example.com" read zero bytes.');

        (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);
    }

    public function test_it_refuses_an_xml_part_whose_octets_are_not_a_document(): void
    {
        // There is no node-set to canonicalize, so there is no digest to compute. Outbound this names the
        // part and its media type: nothing about the caller's own message is a secret from them.
        $part = new ExternalPart('cid:doc@example.com', 'application/xml', $this->stream('<a></b>'));

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessage(
            'Unable to sign the external part "cid:doc@example.com": its application/xml content could not '
            .'be read as a document.'
        );

        (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);
    }

    public function test_it_refuses_an_xml_part_carrying_a_doctype(): void
    {
        // A peer refuses a doctype in an attachment too, so refusing is what keeps the two sides agreeing.
        $part = new ExternalPart('cid:doc@example.com', 'application/xml', $this->stream('<!DOCTYPE a><a/>'));

        $this->expectException(SigningFailed::class);
        (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);
    }

    /**
     * The media types the SwA profile canonicalizes as XML rather than passing through.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function xmlMediaTypes(): iterable
    {
        yield 'application/xml' => ['application/xml'];
        yield 'a soap 1.2 part' => ['application/soap+xml'];
        yield 'svg' => ['image/svg+xml'];
        yield 'parameters carried along' => ['application/xml; charset=utf-8'];
    }

    public function test_it_digests_a_binary_part_whose_type_merely_mentions_xml(): void
    {
        // "+xml" is a structured-syntax suffix, so a subtype that only contains the letters is not XML.
        $part = new ExternalPart('cid:doc@example.com', 'application/xmlish', $this->stream('raw'));

        $result = (new DigestCalculator(new DomCanonicalizer(), new Digest()))
            ->forExternalPart($part, DigestMethod::SHA256, self::SWA_CONTENT);

        static::assertSame(base64_encode(hash('sha256', 'raw', true)), $result->digestValueBase64);
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
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
