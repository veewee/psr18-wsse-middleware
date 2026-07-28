<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateExtractor;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * A peer may carry its whole certification path inline: XML-DSig §4.5.4 allows several ds:X509Certificate
 * elements in one ds:X509Data provided each relates to the validation key or its chain, and its Example 9 does
 * exactly that. Crucially the same section states that <em>no ordering is implied</em>, so the end-entity
 * certificate cannot be taken as the one that happens to appear first — it is the one that issued nothing else
 * in the set. Reading only a single certificate silently discarded the intermediates a chain-to-anchor check
 * needs; picking by position would break on a conformant peer that lists its CA first.
 */
final class InlineCertificateChainTest extends TestCase
{
    public function test_it_reads_a_leaf_and_its_issuer_as_one_chain(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withInlineCertificates(
            $fixture->certificateBase64Der($fixture->leafCertificate),
            $fixture->certificateBase64Der($fixture->caCertificate),
        );

        $chain = $this->extract($document);

        static::assertCount(2, $chain->all());
        static::assertStringContainsString('WSSE Round Trip Leaf', $chain->leaf()->info()->subject()->toString());
        // The issuer must reach the trust check as an untrusted intermediate rather than being dropped.
        static::assertNotNull($chain->intermediatesPem());
    }

    public function test_the_end_entity_is_found_by_issuer_linkage_not_by_document_order(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // The CA is listed first, which XML-DSig permits since no ordering is implied.
        $document = $this->withInlineCertificates(
            $fixture->certificateBase64Der($fixture->caCertificate),
            $fixture->certificateBase64Der($fixture->leafCertificate),
        );

        $chain = $this->extract($document);

        static::assertStringContainsString('WSSE Round Trip Leaf', $chain->leaf()->info()->subject()->toString());
    }

    public function test_a_set_with_no_single_end_entity_is_refused(): void
    {
        // Two unrelated leaves: neither issued the other, so nothing identifies which key signed. Choosing
        // either would let an attacker decide which certificate the signature is checked against.
        $one = WsseSignatureFixture::caSignedLeaf();
        $two = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withInlineCertificates(
            $one->certificateBase64Der($one->leafCertificate),
            $two->certificateBase64Der($two->leafCertificate),
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->extract($document);
    }

    private function extract(Document $document): \Soap\Psr18WsseMiddleware\KeyStore\CertificateChain
    {
        return (new CertificateExtractor(new WsuIdLookup()))
            ->extract($document, $this->signature($document), TrustStore::fromCertificates());
    }

    private function withInlineCertificates(string ...$base64Der): Document
    {
        $certificates = '';
        foreach ($base64Der as $body) {
            $certificates .= '<ds:X509Certificate>'.$body.'</ds:X509Certificate>';
        }

        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
            .' xmlns:ds="'.WsseSignatureFixture::DS.'">'
            .'<soap:Header><wsse:Security><ds:Signature>'
            .'<ds:KeyInfo><ds:X509Data>'.$certificates.'</ds:X509Data></ds:KeyInfo>'
            .'</ds:Signature></wsse:Security></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body></soap:Envelope>'
        );
    }

    private function signature(Document $document): Element
    {
        $signature = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        return $signature;
    }
}
