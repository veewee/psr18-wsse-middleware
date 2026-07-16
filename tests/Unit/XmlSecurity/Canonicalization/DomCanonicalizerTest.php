<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Canonicalization;

use Dom\Comment;
use Dom\Element;
use Dom\XMLDocument;
use DOMDocument;
use DOMElement;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;

final class DomCanonicalizerTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_it_canonicalizes_a_subtree_exclusively(): void
    {
        $body = $this->newBody();

        $output = (new DomCanonicalizer())->canonicalize($body, SignatureCanonicalization::EXC_C14N);

        static::assertNotSame('', $output);
        static::assertStringContainsString('<data>x</data>', $output);
    }

    public function test_an_empty_canonicalization_is_refused(): void
    {
        // A comment node canonicalized without comments yields '' on the new DOM; an empty result must be refused.
        $comment = $this->newBody()->firstChild;
        static::assertInstanceOf(Comment::class, $comment);

        $this->expectException(CanonicalizationFailed::class);
        $this->expectExceptionMessage('empty');
        (new DomCanonicalizer())->canonicalize($comment, SignatureCanonicalization::EXC_C14N);
    }

    public function test_a_native_dom_failure_is_wrapped_not_leaked(): void
    {
        // The new Dom\ API throws DOMException for a detached node (where old libxml returned false). The SPI
        // must surface CanonicalizationFailed, never a raw DOMException.
        $detached = XMLDocument::createFromString('<root/>')->createElement('orphan');

        $this->expectException(CanonicalizationFailed::class);
        (new DomCanonicalizer())->canonicalize($detached, SignatureCanonicalization::EXC_C14N);
    }

    public function test_every_method_can_be_canonicalized(): void
    {
        $canonicalizer = new DomCanonicalizer();

        foreach (SignatureCanonicalization::cases() as $method) {
            $output = $canonicalizer->canonicalize($this->newBody(), $method);
            static::assertNotSame('', $output);
        }
    }

    public function test_comments_are_included_only_for_the_with_comments_method(): void
    {
        $canonicalizer = new DomCanonicalizer();

        $withComments = $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N_COMMENTS);
        $withoutComments = $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N);

        static::assertStringContainsString('<!-- c -->', $withComments);
        static::assertStringNotContainsString('<!-- c -->', $withoutComments);
    }

    // Inclusive C14N carries inherited ancestor namespace declarations into the subtree; exclusive C14N drops
    // the ones the subtree does not use. The 'extra' prefix is declared on the ancestor Envelope and unused in
    // the Body, so it appears only in the inclusive output.
    #[RequiresPhp('>= 8.4.21')]
    public function test_inclusive_c14n_keeps_inherited_ancestor_namespaces_that_exclusive_drops(): void
    {
        $canonicalizer = new DomCanonicalizer();

        $exclusive = $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N);
        $inclusive = $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::C14N);
        $inclusiveComments = $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::C14N_COMMENTS);

        static::assertStringNotContainsString('xmlns:extra', $exclusive);
        static::assertStringContainsString('xmlns:extra', $inclusive);
        static::assertStringContainsString('xmlns:extra', $inclusiveComments);
        static::assertStringContainsString('<!-- c -->', $inclusiveComments);
        static::assertStringNotContainsString('<!-- c -->', $inclusive);
    }

    // Inclusive C14N has no InclusiveNamespaces PrefixList, so a prefix list passed alongside an inclusive
    // method must be ignored rather than changing the output.
    #[RequiresPhp('>= 8.4.21')]
    public function test_a_prefix_list_is_ignored_for_inclusive_c14n(): void
    {
        $canonicalizer = new DomCanonicalizer();

        static::assertSame(
            $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::C14N),
            $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::C14N, ['extra']),
        );
    }

    // The InclusiveNamespaces PrefixList is only honored correctly by libxml on the supported floor.
    #[RequiresPhp('>= 8.4.21')]
    public function test_inclusive_prefixes_force_unused_ancestor_namespaces_into_the_output(): void
    {
        $canonicalizer = new DomCanonicalizer();

        $without = $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N);
        $with = $canonicalizer->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N, ['extra']);

        // The 'extra' prefix is declared on the ancestor Envelope but unused in the Body subtree, so exclusive
        // C14N drops it unless the InclusiveNamespaces PrefixList pins it.
        static::assertStringNotContainsString('xmlns:extra', $without);
        static::assertStringContainsString('xmlns:extra', $with);
    }

    public function test_exclusive_output_is_byte_identical_to_the_legacy_c14n_oracle(): void
    {
        static::assertSame(
            $this->legacyBody()->C14N(true, false),
            (new DomCanonicalizer())->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N),
        );
    }

    public function test_with_comments_matches_the_legacy_oracle(): void
    {
        static::assertSame(
            $this->legacyBody()->C14N(true, true),
            (new DomCanonicalizer())->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N_COMMENTS),
        );
    }

    // The InclusiveNamespaces PrefixList is only honored correctly by libxml on the supported floor.
    #[RequiresPhp('>= 8.4.21')]
    public function test_prefixlist_matches_the_legacy_oracle(): void
    {
        static::assertSame(
            $this->legacyBody()->C14N(true, false, null, ['extra']),
            (new DomCanonicalizer())->canonicalize($this->newBody(), SignatureCanonicalization::EXC_C14N, ['extra']),
        );
    }

    /**
     * The mutate-then-canonicalize path (set wsu:Id, then C14N) is the CVE-2026-7263 / GH-21548 trigger: on
     * an unpatched libxml it corrupts the attribute list (DoS). On the >= 8.4.21 floor it must produce bytes
     * identical to the legacy oracle.
     */
    #[RequiresPhp('>= 8.4.21')]
    public function test_mutation_path_is_byte_identical_to_the_legacy_oracle(): void
    {
        $newBody = $this->newBody();
        $newBody->setAttributeNS(self::WSU, 'wsu:Id', 'Body-Signed');

        $legacyBody = $this->legacyBody();
        $legacyBody->setAttributeNS(self::WSU, 'wsu:Id', 'Body-Signed');

        static::assertSame(
            $legacyBody->C14N(true, false),
            (new DomCanonicalizer())->canonicalize($newBody, SignatureCanonicalization::EXC_C14N),
        );
    }

    private function newBody(): Element
    {
        $document = XMLDocument::createFromString($this->envelope());
        $body = $document->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }

    private function legacyBody(): DOMElement
    {
        $document = new DOMDocument();
        static::assertTrue($document->loadXML($this->envelope()));
        $body = $document->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(DOMElement::class, $body);

        return $body;
    }

    /**
     * @return non-empty-string
     */
    private function envelope(): string
    {
        return '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsu="'.self::WSU.'" xmlns:extra="urn:extra">'
            .'<soap:Header/>'
            .'<soap:Body wsu:Id="Body-1"><!-- c --><data>x</data></soap:Body>'
            .'</soap:Envelope>';
    }
}
