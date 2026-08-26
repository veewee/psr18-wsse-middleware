<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\SecurityTokenReferenceTransform;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ParsedReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ResolvedVerificationReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use VeeWee\Xml\Dom\Document;

/**
 * The seam a dereferencing transform opens, across the three units that carry it: the parser records which
 * transform a reference declared, the resolver hands the reference to it, and the digest verifier digests what
 * came back rather than the element the URI named.
 */
final class DereferencingTransformTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const STR_TRANSFORM = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#STR-Transform';

    public function test_the_parser_records_the_transform_a_reference_declared(): void
    {
        $parsed = (new SignedInfoParser())
            ->parse($this->signature($this->document()), new SecurityTokenReferenceTransform());

        static::assertSame(self::STR_TRANSFORM, $parsed->references[0]->dereferencingTransform);
    }

    public function test_the_parser_keeps_the_transformation_parameters_canonicalization_on_the_reference(): void
    {
        // Holding it here rather than somewhere new is what lets AlgorithmPolicyEnforcer gate it with no
        // change: the transform's inner method is allow-listed exactly like any other reference's.
        $parsed = (new SignedInfoParser())
            ->parse($this->signature($this->document()), new SecurityTokenReferenceTransform());

        static::assertSame(SignatureCanonicalization::EXC_C14N, $parsed->references[0]->canonicalization);
    }

    public function test_the_parser_refuses_the_transform_when_none_is_registered(): void
    {
        // The engine on its own knows nothing about WS-Security, so an unregistered transform stays unknown.
        $this->expectException(SignatureVerificationFailed::class);
        (new SignedInfoParser())->parse($this->signature($this->document()));
    }

    public function test_the_parser_refuses_a_transform_another_implementation_claims(): void
    {
        $parser = new SignedInfoParser();
        $document = $this->document(transform: 'urn:some-other-transform');

        $this->expectException(SignatureVerificationFailed::class);
        $parser->parse($this->signature($document), new SecurityTokenReferenceTransform());
    }

    public function test_the_allow_list_refuses_an_inclusive_canonicalization_named_inside_the_transform(): void
    {
        // The reason the transform's method is kept on the reference rather than somewhere new: the existing
        // per-reference allow-list gates it, so a peer cannot reach inclusive c14n by naming it one level down.
        $parsed = (new SignedInfoParser())->parse(
            $this->signature($this->document(canonicalization: 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315')),
            new SecurityTokenReferenceTransform(),
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new AlgorithmPolicyEnforcer())->enforce(
            new VerificationPolicy(TrustStore::fromCertificates(), CryptoPolicy::default()),
            $parsed,
        );
    }

    public function test_the_resolver_reports_what_the_transform_dereferenced(): void
    {
        $document = $this->document();
        $resolved = $this->resolve($document);

        static::assertNotNull($resolved->dereferenced);
        static::assertSame($this->byId($document, 'bst-1'), $resolved->dereferenced);
        static::assertSame($resolved->dereferenced, $resolved->digested());

        // The element the URI named is still reported as the reference's own, so nothing loses track of which
        // reference this was.
        static::assertSame($this->byId($document, 'str-1'), $resolved->element);
    }

    public function test_the_resolver_accepts_an_indirection_inside_the_signature(): void
    {
        // This is the shape WSS4J actually emits: it points the reference at the
        // wsse:SecurityTokenReference it built inside its own ds:KeyInfo, not at a standalone one in the
        // header. An ordinary reference resolving inside the signature is signature-wrapping and stays
        // refused, but here the digested bytes are the dereferenced token's, which is checked separately,
        // so the indirection itself sitting in ds:KeyInfo is exactly correct.
        $document = $this->wss4jShapedDocument();
        $resolved = $this->resolve($document, signature: $this->signature($document));

        static::assertSame($this->byId($document, 'bst-1'), $resolved->dereferenced);
    }

    public function test_the_resolver_still_refuses_a_dereferenced_token_inside_the_signature(): void
    {
        // The relaxation above covers the indirection only. A token that resolves into the signature would
        // be the signature vouching for its own bytes.
        $document = $this->wss4jShapedDocument(tokenInsideSignature: true);

        $this->expectException(SignatureVerificationFailed::class);
        $this->resolve($document, signature: $this->signature($document));
    }

    public function test_the_resolver_refuses_the_transform_when_none_is_registered(): void
    {
        $document = $this->document();

        $this->expectException(SignatureVerificationFailed::class);
        $this->resolve($document, transform: null);
    }

    public function test_the_digest_verifier_digests_the_dereferenced_token(): void
    {
        $document = $this->document();
        $token = $this->byId($document, 'bst-1');

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());
        $resolved = $this->resolve($document, expectedDigestOf: $token);

        static::assertTrue($verifier->verify($resolved));
    }

    public function test_the_digest_verifier_refuses_a_digest_taken_over_the_reference_itself(): void
    {
        // The whole point of the transform: digesting the wsse:SecurityTokenReference is the wrong answer, and
        // must not verify just because that is the element the URI named.
        $document = $this->document();
        $reference = $this->byId($document, 'str-1');

        $verifier = new DigestVerifier(new DomCanonicalizer(), new Digest());
        $resolved = $this->resolve($document, expectedDigestOf: $reference);

        static::assertFalse($verifier->verify($resolved));
    }

    private function resolve(
        Document $document,
        ?SecurityTokenReferenceTransform $transform = new SecurityTokenReferenceTransform(),
        ?Element $expectedDigestOf = null,
        ?Element $signature = null,
    ): ResolvedVerificationReference {
        $parsed = (new SignedInfoParser())->parse($this->signature($document), new SecurityTokenReferenceTransform());
        $references = $parsed->references;

        if ($expectedDigestOf !== null) {
            $references = [$this->withExpectedDigest($references[0], $expectedDigestOf)];
        }

        $resolved = (new ReferenceResolver((new WsuIdConvention())->lookup(), $transform))->resolve(
            $document,
            $parsed->referenceElements,
            $references,
            $signature ?? $this->signature($document),
        );

        return $resolved[0];
    }

    /**
     * The digest a signer would have produced over a given element under the transform's canonicalization,
     * computed with the same primitives the verifier uses.
     */
    private function withExpectedDigest(ParsedReference $reference, Element $element): ParsedReference
    {
        $canonical = (new DomCanonicalizer())->canonicalize(
            $element,
            SignatureCanonicalization::EXC_C14N,
            ['#default'],
        );

        return new ParsedReference(
            DigestMethod::SHA256,
            base64_encode((new Digest())->hash($canonical, DigestMethod::SHA256)),
            $reference->canonicalization,
            $reference->inclusivePrefixes,
            $reference->dereferencingTransform,
        );
    }

    private function document(
        string $transform = self::STR_TRANSFORM,
        string $canonicalization = self::EXC_C14N,
    ): Document {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security>'
            .'<wsse:BinarySecurityToken wsu:Id="bst-1">Y2VydGlmaWNhdGU=</wsse:BinarySecurityToken>'
            .'<wsse:SecurityTokenReference wsu:Id="str-1"><wsse:Reference URI="#bst-1"/></wsse:SecurityTokenReference>'
            .'<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignedInfo>'
            .'<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>'
            .'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            .'<ds:Reference URI="#str-1"><ds:Transforms>'
            .'<ds:Transform Algorithm="'.$transform.'">'
            .'<wsse:TransformationParameters>'
            .'<ds:CanonicalizationMethod Algorithm="'.$canonicalization.'"/>'
            .'</wsse:TransformationParameters>'
            .'</ds:Transform></ds:Transforms>'
            .'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            .'<ds:DigestValue>'.base64_encode('not-the-digest').'</ds:DigestValue>'
            .'</ds:Reference>'
            .'</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>'
            .'</wsse:Security></soap:Header>'
            .'<soap:Body wsu:Id="Body"><data>x</data></soap:Body></soap:Envelope>',
        );
    }


    /**
     * The envelope WSS4J emits for a token covered through STR-Transform: the ds:Reference points at the
     * wsse:SecurityTokenReference that lives inside the signature's own ds:KeyInfo.
     */
    private function wss4jShapedDocument(bool $tokenInsideSignature = false): Document
    {
        $token = '<wsse:BinarySecurityToken wsu:Id="bst-1">Y2VydGlmaWNhdGU=</wsse:BinarySecurityToken>';

        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'" xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security>'
            .($tokenInsideSignature ? '' : $token)
            .'<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignedInfo>'
            .'<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>'
            .'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            .'<ds:Reference URI="#str-1"><ds:Transforms>'
            .'<ds:Transform Algorithm="'.self::STR_TRANSFORM.'">'
            .'<wsse:TransformationParameters>'
            .'<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>'
            .'</wsse:TransformationParameters>'
            .'</ds:Transform></ds:Transforms>'
            .'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            .'<ds:DigestValue>'.base64_encode('not-the-digest').'</ds:DigestValue>'
            .'</ds:Reference>'
            .'</ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue>'
            .'<ds:KeyInfo>'
            .'<wsse:SecurityTokenReference wsu:Id="str-1"><wsse:Reference URI="#bst-1"/></wsse:SecurityTokenReference>'
            .($tokenInsideSignature ? $token : '')
            .'</ds:KeyInfo>'
            .'</ds:Signature>'
            .'</wsse:Security></soap:Header>'
            .'<soap:Body wsu:Id="Body"><data>x</data></soap:Body></soap:Envelope>',
        );
    }

    private function signature(Document $document): Element
    {
        $signature = $document->toUnsafeDocument()->getElementsByTagNameNS(self::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        return $signature;
    }

    private function byId(Document $document, string $id): Element
    {
        foreach ($document->toUnsafeDocument()->getElementsByTagName('*') as $element) {
            if ($element instanceof Element && $element->getAttributeNS(self::WSU, 'Id') === $id) {
                return $element;
            }
        }

        static::fail(sprintf('No element with wsu:Id "%s".', $id));
    }
}
