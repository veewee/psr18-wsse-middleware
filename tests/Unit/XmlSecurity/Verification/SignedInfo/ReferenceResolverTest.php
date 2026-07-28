<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ParsedReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

final class ReferenceResolverTest extends TestCase
{
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const XSLT = 'http://www.w3.org/TR/1999/REC-xslt-19991116';
    private const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    public function test_it_resolves_a_known_wsu_id_to_the_exact_element(): void
    {
        $document = $this->document(['Body' => self::reference('#Body', self::EXC_C14N)]);
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertCount(1, $resolved);
        static::assertSame($this->byId($document, 'Body'), $resolved[0]->element);
    }

    public function test_it_rejects_a_duplicate_wsu_id(): void
    {
        $document = $this->document(['Body' => self::reference('#Dup', self::EXC_C14N)], duplicateId: 'Dup');
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_resolves_a_reference_that_declares_no_transforms(): void
    {
        $document = $this->document(['Body' => self::referenceWithoutTransforms('#Body')]);
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertSame($this->byId($document, 'Body'), $resolved[0]->element);
    }

    public function test_the_parser_and_the_resolver_agree_on_an_absent_transforms(): void
    {
        // The two used to contradict each other: the parser fell back to the SignedInfo canonicalization
        // while the resolver refused the same reference outright, leaving the tolerant branch unreachable.
        $document = $this->document(['Body' => self::referenceWithoutTransforms('#Body')]);
        $signature = $this->signature($document);

        $parsed = (new SignedInfoParser())->parse($signature);

        // Inclusive c14n, the XML-DSig default for a node-set with no transform — not the EXC_C14N this
        // fixture's SignedInfo declares for itself.
        static::assertSame(SignatureCanonicalization::C14N, $parsed->references[0]->canonicalization);
        static::assertSame([], $parsed->references[0]->inclusivePrefixes);

        $resolved = (new ReferenceResolver(new WsuIdLookup()))
            ->resolve($document, $parsed->referenceElements, $parsed->references, $signature);

        static::assertSame($this->byId($document, 'Body'), $resolved[0]->element);
    }

    public function test_it_rejects_an_xslt_transform(): void
    {
        $document = $this->document(['Body' => self::reference('#Body', self::XSLT)]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_rejects_an_enveloped_signature_transform(): void
    {
        // This library signs detached, and its references name a c14n transform only. An enveloped-signature
        // transform changes what the digest covers, so it is refused rather than quietly honoured.
        $document = $this->document(['Body' => self::reference('#Body', self::ENVELOPED_SIGNATURE)]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_rejects_an_unknown_transform(): void
    {
        $document = $this->document(['Body' => self::reference('#Body', 'urn:made-up-transform')]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_rejects_an_external_uri(): void
    {
        $document = $this->document(['Body' => self::reference('http://attacker.example/', self::EXC_C14N)]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_rejects_a_reference_to_the_signature_itself(): void
    {
        $document = $this->document(['Sig' => self::reference('#TheSignature', self::EXC_C14N)]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_rejects_a_reference_count_over_the_cap_before_resolving(): void
    {
        $count = ReferenceResolver::MAX_REFERENCES + 1;
        $document = Document::fromXmlString($this->envelope(''));

        // None of the references even need to point at a real element: the cap is checked first.
        $element = $this->byId($document, 'Body');
        $referenceElements = array_fill(0, $count, $element);
        $parsed = array_fill(
            0,
            $count,
            new ParsedReference(DigestMethod::SHA256, base64_encode('x'), SignatureCanonicalization::EXC_C14N, []),
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver(new WsuIdLookup()))->resolve($document, $referenceElements, $parsed, $this->signature($document));
    }

    private static function reference(string $uri, string $transform): string
    {
        return '<ds:Reference URI="'.$uri.'">'
            .'<ds:Transforms><ds:Transform Algorithm="'.$transform.'"/></ds:Transforms>'
            .self::digest()
            .'</ds:Reference>';
    }

    private static function referenceWithoutTransforms(string $uri): string
    {
        return '<ds:Reference URI="'.$uri.'">'.self::digest().'</ds:Reference>';
    }

    private static function digest(): string
    {
        return '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            .'<ds:DigestValue>'.base64_encode('digest').'</ds:DigestValue>';
    }

    /**
     * @param array<string, string> $references map of marker to ds:Reference markup
     */
    private function document(array $references, ?string $duplicateId = null): Document
    {
        $duplicate = $duplicateId !== null
            ? '<dup wsu:Id="'.$duplicateId.'"/><dup wsu:Id="'.$duplicateId.'"/>'
            : '';

        return Document::fromXmlString($this->envelope(implode('', $references), $duplicate));
    }

    private function envelope(string $references, string $duplicate = ''): string
    {
        return '<soap:Envelope'
            .' xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
            .' xmlns:wsu="'.WsseSignatureFixture::WSU.'"'
            .' xmlns:ds="'.WsseSignatureFixture::DS.'">'
            .'<soap:Header><wsse:Security>'
            .$duplicate
            .'<ds:Signature wsu:Id="TheSignature"><ds:SignedInfo>'
            .'<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>'
            .'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            .$references.'</ds:SignedInfo></ds:Signature>'
            .'</wsse:Security></soap:Header>'
            .'<soap:Body wsu:Id="Body"><data>x</data></soap:Body></soap:Envelope>';
    }

    /**
     * @return array{0: non-empty-list<Element>, 1: non-empty-list<ParsedReference>}
     */
    private function references(Document $document): array
    {
        $signedInfo = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'SignedInfo')->item(0);
        static::assertInstanceOf(Element::class, $signedInfo);

        $elements = [];
        $parsed = [];
        foreach ($signedInfo->childNodes as $child) {
            if ($child instanceof Element && $child->localName === 'Reference') {
                $elements[] = $child;
                $parsed[] = new ParsedReference(DigestMethod::SHA256, base64_encode('digest'), SignatureCanonicalization::EXC_C14N, []);
            }
        }

        static::assertNotEmpty($elements);

        return [$elements, $parsed];
    }

    private function signature(Document $document): Element
    {
        $signature = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        return $signature;
    }

    private function byId(Document $document, string $id): Element
    {
        $matches = $document->toUnsafeDocument()->getElementsByTagName('*');
        foreach ($matches as $element) {
            if ($element instanceof Element
                && $element->getAttributeNS(WsseSignatureFixture::WSU, 'Id') === $id
            ) {
                return $element;
            }
        }

        static::fail(sprintf('No element with wsu:Id "%s".', $id));
    }
}
