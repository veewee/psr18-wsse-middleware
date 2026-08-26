<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\External\ExternalPartVerification;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ParsedReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

final class ReferenceResolverTest extends TestCase
{
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const SWA_CONTENT = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform';
    private const XSLT = 'http://www.w3.org/TR/1999/REC-xslt-19991116';
    private const ENVELOPED_SIGNATURE = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
    private const XOP = 'http://www.w3.org/2004/08/xop/include';
    private const BODY = '<data>x</data>';
    private const UNCOVERED_POINTER = 'A signed element points at content the signature does not cover.';

    public function test_it_resolves_a_known_wsu_id_to_the_exact_element(): void
    {
        $document = $this->document(['Body' => self::reference('#Body', self::EXC_C14N)]);
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertCount(1, $resolved->elements);
        static::assertSame($this->byId($document, 'Body'), $resolved->elements[0]->element);
    }

    public function test_it_rejects_a_duplicate_wsu_id(): void
    {
        $document = $this->document(['Body' => self::reference('#Dup', self::EXC_C14N)], duplicateId: 'Dup');
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_resolves_a_reference_that_declares_no_transforms(): void
    {
        $document = $this->document(['Body' => self::referenceWithoutTransforms('#Body')]);
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertSame($this->byId($document, 'Body'), $resolved->elements[0]->element);
    }

    public function test_the_parser_and_the_resolver_agree_on_an_absent_transforms(): void
    {
        // The two used to contradict each other: the parser fell back to the SignedInfo canonicalization
        // while the resolver refused the same reference outright, leaving the tolerant branch unreachable.
        $document = $this->document(['Body' => self::referenceWithoutTransforms('#Body')]);
        $signature = $this->signature($document);

        $parsed = (new SignedInfoParser())->parse($signature);

        // Inclusive c14n, the XML-DSig default for a node-set with no transform, not the EXC_C14N this
        // fixture's SignedInfo declares for itself.
        static::assertSame(SignatureCanonicalization::C14N, $parsed->references[0]->canonicalization);
        static::assertSame([], $parsed->references[0]->inclusivePrefixes);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))
            ->resolve($document, $parsed->referenceElements, $parsed->references, $signature);

        static::assertSame($this->byId($document, 'Body'), $resolved->elements[0]->element);
    }

    public function test_it_rejects_an_xslt_transform(): void
    {
        $document = $this->document(['Body' => self::reference('#Body', self::XSLT)]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_accepts_an_enveloped_signature_transform_over_the_element_holding_the_signature(): void
    {
        // A signature that signs the element it sits inside must exclude itself from the digest, which is what
        // this transform means and is the shape a signed SAML assertion arrives in.
        $document = $this->enveloped(self::transforms([self::ENVELOPED_SIGNATURE, self::EXC_C14N]));
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertCount(1, $resolved->elements);
        static::assertSame($this->byId($document, 'Assertion'), $resolved->elements[0]->element);
        // The signature to strip is carried forward by identity, so the digest excludes that exact subtree.
        static::assertSame($this->signature($document), $resolved->elements[0]->envelopedSignature);
    }

    public function test_it_accepts_an_enveloped_signature_transform_on_its_own(): void
    {
        // Legal per XML-DSig: with no canonicalization named, the default applies, exactly as for a reference
        // that declares no transforms at all. Some signers emit this form.
        $document = $this->enveloped(self::transforms([self::ENVELOPED_SIGNATURE]));
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertSame($this->signature($document), $resolved->elements[0]->envelopedSignature);
    }

    public function test_it_refuses_a_second_signature_inside_the_digested_element(): void
    {
        // The wrapping lever. Stripping every ds:Signature under the element would silently drop an injected
        // one from the digest, so more than one is refused outright rather than resolved by picking.
        $document = $this->enveloped(
            self::transforms([self::ENVELOPED_SIGNATURE, self::EXC_C14N]),
            extra: '<ds:Signature wsu:Id="Injected"><ds:SignedInfo/></ds:Signature>',
        );
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_refuses_an_enveloped_signature_transform_when_the_element_holds_no_signature(): void
    {
        // The transform claims self-exclusion while the signature sits elsewhere, which is a relocated
        // signature claiming to cover an element it is not inside.
        $document = $this->document(['Body' => self::referenceWith('#Body', self::transforms([self::ENVELOPED_SIGNATURE, self::EXC_C14N]))]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_refuses_a_canonicalization_declared_before_the_enveloped_signature_transform(): void
    {
        // Transforms are an ordered pipeline: canonicalizing first and stripping afterwards is a different
        // computation, so the reversed order is a different claim and is not accepted as equivalent.
        $document = $this->enveloped(self::transforms([self::EXC_C14N, self::ENVELOPED_SIGNATURE]));
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_a_detached_reference_carries_no_signature_to_strip(): void
    {
        $document = $this->document(['Body' => self::reference('#Body', self::EXC_C14N)]);
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertNull($resolved->elements[0]->envelopedSignature);
    }

    public function test_it_rejects_an_unknown_transform(): void
    {
        $document = $this->document(['Body' => self::reference('#Body', 'urn:made-up-transform')]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_rejects_an_external_uri(): void
    {
        $document = $this->document(['Body' => self::reference('http://attacker.example/', self::EXC_C14N)]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_rejects_a_reference_to_the_signature_itself(): void
    {
        $document = $this->document(['Sig' => self::reference('#TheSignature', self::EXC_C14N)]);
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $elements, $parsed, $this->signature($document));
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
        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve($document, $referenceElements, $parsed, $this->signature($document));
    }

    /**
     * @param list<string> $algorithms
     */
    private static function transforms(array $algorithms): string
    {
        $transforms = '';
        foreach ($algorithms as $algorithm) {
            $transforms .= '<ds:Transform Algorithm="'.$algorithm.'"/>';
        }

        return '<ds:Transforms>'.$transforms.'</ds:Transforms>';
    }

    private static function referenceWith(string $uri, string $transforms): string
    {
        return '<ds:Reference URI="'.$uri.'">'.$transforms.self::digest().'</ds:Reference>';
    }

    /**
     * An envelope whose signature sits inside the element it signs, the enveloped shape.
     */
    private function enveloped(string $transforms, string $extra = ''): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
            .' xmlns:wsu="'.WsseSignatureFixture::WSU.'"'
            .' xmlns:ds="'.WsseSignatureFixture::DS.'">'
            .'<soap:Header><wsse:Security>'
            .'<a:Assertion xmlns:a="urn:assertion" wsu:Id="Assertion"><a:Payload>signed</a:Payload>'
            .'<ds:Signature wsu:Id="TheSignature"><ds:SignedInfo>'
            .'<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>'
            .'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            .self::referenceWith('#Assertion', $transforms)
            .'</ds:SignedInfo></ds:Signature>'
            .$extra
            .'</a:Assertion>'
            .'</wsse:Security></soap:Header>'
            .'<soap:Body wsu:Id="Body"><data>x</data></soap:Body></soap:Envelope>'
        );
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
    private function document(
        array $references,
        ?string $duplicateId = null,
        string $body = self::BODY,
    ): Document {
        $duplicate = $duplicateId !== null
            ? '<dup wsu:Id="'.$duplicateId.'"/><dup wsu:Id="'.$duplicateId.'"/>'
            : '';

        return Document::fromXmlString($this->envelope(implode('', $references), $duplicate, $body));
    }

    private function envelope(string $references, string $duplicate = '', string $body = self::BODY): string
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
            .'<soap:Body wsu:Id="Body">'.$body.'</soap:Body></soap:Envelope>';
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

    public function test_an_external_reference_resolves_to_the_part_its_uri_names(): void
    {
        $document = $this->document([self::reference('cid:b@example.com', self::SWA_CONTENT)]);
        [$elements, $parsed] = $this->parsedExternal($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve(
            $document,
            $elements,
            $parsed,
            $this->signature($document),
            new ExternalPartVerification(
                ExternalPartList::of($this->part('cid:a@example.com'), $wanted = $this->part('cid:b@example.com')),
                self::SWA_CONTENT,
            ),
        );

        static::assertSame([], $resolved->elements);
        static::assertCount(1, $resolved->external);
        // The part its URI names, not merely some part that was supplied: picking any other one would let a
        // signature over one attachment be checked against a different file.
        static::assertSame($wanted, $resolved->external[0]->part);
    }

    public function test_an_external_reference_naming_no_supplied_part_is_refused(): void
    {
        $document = $this->document([self::reference('cid:stranger@example.com', self::SWA_CONTENT)]);
        [$elements, $parsed] = $this->parsedExternal($document);

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('A referenced element could not be resolved.');

        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve(
            $document,
            $elements,
            $parsed,
            $this->signature($document),
            new ExternalPartVerification(
                ExternalPartList::of($this->part('cid:a@example.com')),
                self::SWA_CONTENT,
            ),
        );
    }

    public function test_it_refuses_an_element_pointing_at_content_no_part_covers(): void
    {
        // The shape a WSS4J peer sends with expandXopInclude off: the Body is signed, its content is a
        // pointer, and nothing in the signature says anything about the bytes the pointer names. Accepting it
        // would report the file as signed while an intermediary is free to replace it.
        $document = $this->document(
            ['Body' => self::reference('#Body', self::EXC_C14N)],
            body: $this->optimizedBody('cid:invoice@example.com'),
        );
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage(self::UNCOVERED_POINTER);

        (new ReferenceResolver((new WsuIdConvention())->lookup()))
            ->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_refuses_an_element_pointing_at_a_part_that_was_not_supplied(): void
    {
        $document = $this->document(
            ['Body' => self::reference('#Body', self::EXC_C14N)],
            body: $this->optimizedBody('cid:invoice@example.com'),
        );
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage(self::UNCOVERED_POINTER);

        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve(
            $document,
            $elements,
            $parsed,
            $this->signature($document),
            new ExternalPartVerification(
                ExternalPartList::of($this->part('cid:other@example.com')),
                self::SWA_CONTENT,
            ),
        );
    }

    public function test_it_refuses_an_element_pointing_at_nothing(): void
    {
        $document = $this->document(
            ['Body' => self::reference('#Body', self::EXC_C14N)],
            body: '<data><xop:Include xmlns:xop="'.self::XOP.'"/></data>',
        );
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage(self::UNCOVERED_POINTER);

        (new ReferenceResolver((new WsuIdConvention())->lookup()))
            ->resolve($document, $elements, $parsed, $this->signature($document));
    }

    public function test_it_accepts_an_element_pointing_at_a_part_this_signature_also_covers(): void
    {
        // The supported MTOM shape: the element points at a part, and the same ds:SignedInfo carries a
        // reference digesting that part's octets. Both the pointer and the bytes are covered.
        $document = $this->document(
            [
                'Body' => self::reference('#Body', self::EXC_C14N),
                'Part' => self::reference('cid:invoice@example.com', self::SWA_CONTENT),
            ],
            body: $this->optimizedBody('cid:invoice@example.com'),
        );
        [$elements, $parsed] = $this->parsedExternal($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve(
            $document,
            $elements,
            $parsed,
            $this->signature($document),
            new ExternalPartVerification(
                ExternalPartList::of($this->part('cid:invoice@example.com')),
                self::SWA_CONTENT,
            ),
        );

        static::assertSame($this->byId($document, 'Body'), $resolved->elements[0]->element);
        static::assertCount(1, $resolved->external);
    }

    public function test_it_refuses_an_element_pointing_at_a_supplied_part_this_signature_does_not_cover(): void
    {
        // The gap a membership check leaves open. The part is in the list the caller supplied, so it exists
        // and it arrived, but no reference in this ds:SignedInfo digests it: the signature says nothing about
        // those bytes, and an intermediary is free to replace them. Being available is not being covered.
        $document = $this->document(
            ['Body' => self::reference('#Body', self::EXC_C14N)],
            body: $this->optimizedBody('cid:invoice@example.com'),
        );
        [$elements, $parsed] = $this->references($document);

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage(self::UNCOVERED_POINTER);

        (new ReferenceResolver((new WsuIdConvention())->lookup()))->resolve(
            $document,
            $elements,
            $parsed,
            $this->signature($document),
            new ExternalPartVerification(
                ExternalPartList::of($this->part('cid:invoice@example.com')),
                self::SWA_CONTENT,
            ),
        );
    }

    public function test_it_leaves_a_pointer_outside_the_signed_element_alone(): void
    {
        // Only what a reference covers is this rule's business. A pointer elsewhere in the message says
        // nothing about the element being digested, and refusing on it would reject a message whose signed
        // region is entirely self-contained.
        $document = $this->document(
            ['Inner' => self::reference('#Inner', self::EXC_C14N)],
            body: '<inner wsu:Id="Inner">x</inner>'.$this->optimizedBody('cid:invoice@example.com'),
        );
        [$elements, $parsed] = $this->references($document);

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup()))
            ->resolve($document, $elements, $parsed, $this->signature($document));

        static::assertSame($this->byId($document, 'Inner'), $resolved->elements[0]->element);
    }

    private function optimizedBody(string $reference): string
    {
        return '<data><xop:Include xmlns:xop="'.self::XOP.'" href="'.$reference.'"/></data>';
    }

    /**
     * @return array{0: non-empty-list<Element>, 1: non-empty-list<ParsedReference>}
     */
    private function parsedExternal(Document $document): array
    {
        $parsed = (new SignedInfoParser())->parse($this->signature($document), self::SWA_CONTENT);

        return [$parsed->referenceElements, $parsed->references];
    }

    private function part(string $reference): ExternalPart
    {
        return new ExternalPart($reference, 'application/pdf', MemoryStream::create());
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
