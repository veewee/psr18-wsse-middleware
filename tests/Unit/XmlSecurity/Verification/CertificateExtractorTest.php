<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\CertificateExtractor;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * Covers the inbound CertificateExtractor: it reads the two forms that carry the certificate in the message (a
 * BST direct reference and an inline ds:X509Certificate), and resolves the three forms that name the certificate
 * by identifier (Subject Key Identifier, SHA-1 thumbprint, IssuerSerial) against the verifier's trust store. A
 * reference to a certificate the trust store does not hold is refused, and an ambiguous match is refused.
 */
final class CertificateExtractorTest extends TestCase
{
    private const X509_TOKEN = WsseSignatureFixture::X509_TOKEN;
    private const WSSE11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';

    public function test_it_reads_the_certificate_from_a_referenced_binary_security_token(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $base64Der = $fixture->certificateBase64Der($fixture->leafCertificate);
        $document = $this->document(
            '<wsse:BinarySecurityToken wsu:Id="SignedToken" ValueType="'.self::X509_TOKEN.'">'.$base64Der.'</wsse:BinarySecurityToken>',
            '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:Reference URI="#SignedToken" ValueType="'.self::X509_TOKEN.'"/>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>'
        );

        $chain = $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());

        static::assertStringContainsString('CERTIFICATE', $chain->leaf()->contents());
    }

    public function test_it_reads_an_inline_x509_certificate(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $base64Der = $fixture->certificateBase64Der($fixture->leafCertificate);
        $document = $this->document(
            '',
            '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>'.$base64Der.'</ds:X509Certificate></ds:X509Data></ds:KeyInfo>'
        );

        $chain = $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());

        static::assertStringContainsString('CERTIFICATE', $chain->leaf()->contents());
    }

    public function test_it_rejects_a_missing_key_info(): void
    {
        $document = $this->document('', '');

        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());
    }

    public function test_it_rejects_a_reference_to_a_missing_token(): void
    {
        $document = $this->document(
            '',
            '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:Reference URI="#NoSuchToken" ValueType="'.self::X509_TOKEN.'"/>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>'
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());
    }

    public function test_it_rejects_a_token_with_an_unsupported_value_type(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $base64Der = $fixture->certificateBase64Der($fixture->leafCertificate);
        $document = $this->document(
            '<wsse:BinarySecurityToken wsu:Id="SignedToken" ValueType="urn:unsupported">'.$base64Der.'</wsse:BinarySecurityToken>',
            '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:Reference URI="#SignedToken" ValueType="'.self::X509_TOKEN.'"/>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>'
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());
    }

    public function test_it_rejects_a_token_with_a_present_but_unsupported_encoding_type(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $base64Der = $fixture->certificateBase64Der($fixture->leafCertificate);
        $document = $this->document(
            '<wsse:BinarySecurityToken wsu:Id="SignedToken" ValueType="'.self::X509_TOKEN.'"'
            .' EncodingType="urn:unsupported-encoding">'.$base64Der.'</wsse:BinarySecurityToken>',
            '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:Reference URI="#SignedToken" ValueType="'.self::X509_TOKEN.'"/>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>'
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());
    }

    public function test_it_reads_a_token_with_the_base64_encoding_type_present(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $base64Der = $fixture->certificateBase64Der($fixture->leafCertificate);
        $base64Encoding = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';
        $document = $this->document(
            '<wsse:BinarySecurityToken wsu:Id="SignedToken" ValueType="'.self::X509_TOKEN.'"'
            .' EncodingType="'.$base64Encoding.'">'.$base64Der.'</wsse:BinarySecurityToken>',
            '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:Reference URI="#SignedToken" ValueType="'.self::X509_TOKEN.'"/>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>'
        );

        $chain = $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());

        static::assertStringContainsString('CERTIFICATE', $chain->leaf()->contents());
    }

    public function test_it_reads_a_token_with_an_absent_encoding_type(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $base64Der = $fixture->certificateBase64Der($fixture->leafCertificate);
        $document = $this->document(
            '<wsse:BinarySecurityToken wsu:Id="SignedToken" ValueType="'.self::X509_TOKEN.'">'.$base64Der.'</wsse:BinarySecurityToken>',
            '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:Reference URI="#SignedToken" ValueType="'.self::X509_TOKEN.'"/>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>'
        );

        $chain = $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());

        static::assertStringContainsString('CERTIFICATE', $chain->leaf()->contents());
    }

    public function test_it_resolves_a_signer_referenced_by_subject_key_identifier(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withKeyInfo(
            new X509SubjectKeyIdentifier(),
            $fixture->leafCertificate,
        );

        $chain = $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($this->base64Der($fixture->leafCertificate), $this->base64Der($chain->leaf()));
    }

    public function test_it_resolves_a_signer_referenced_by_sha1_thumbprint(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withKeyInfo(
            new ThumbprintKeyIdentifier(),
            $fixture->leafCertificate,
        );

        $chain = $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($this->base64Der($fixture->leafCertificate), $this->base64Der($chain->leaf()));
    }

    public function test_it_resolves_a_signer_referenced_by_issuer_and_serial(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withKeyInfo(
            new IssuerSerialKeyIdentifier(),
            $fixture->leafCertificate,
        );

        // A second, unrelated trust anchor has a different issuer DN, so the issuer-serial match stays unique.
        $other = WsseSignatureFixture::selfSignedLeaf();

        $chain = $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($other->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($this->base64Der($fixture->leafCertificate), $this->base64Der($chain->leaf()));
    }

    public function test_it_refuses_an_identifier_reference_to_a_certificate_not_in_the_trust_store(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withKeyInfo(
            new X509SubjectKeyIdentifier(),
            $fixture->leafCertificate,
        );

        // The trust store holds only the CA, not the signer leaf, so the identifier cannot be resolved.
        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->caCertificate),
        );
    }

    public function test_it_refuses_an_ambiguous_subject_key_identifier_match(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withKeyInfo(
            new X509SubjectKeyIdentifier(),
            $fixture->leafCertificate,
        );

        // Two trust-store entries with the same identifier make the reference ambiguous.
        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->leafCertificate, $fixture->leafCertificate),
        );
    }

    private function extractor(): CertificateExtractor
    {
        return new CertificateExtractor();
    }

    /**
     * Builds an envelope whose ds:Signature carries a ds:KeyInfo produced by the given outbound key-identifier
     * strategy for the given certificate, the form a conformant peer emits when it names the signer by identifier.
     */
    private function withKeyInfo(KeyIdentifier $strategy, Certificate $certificate): Document
    {
        $document = $this->document('', '<ds:KeyInfoPlaceholder/>');
        $native = $document->toUnsafeDocument();

        $signature = $native->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);
        $placeholder = $native->getElementsByTagNameNS(WsseSignatureFixture::DS, 'KeyInfoPlaceholder')->item(0);
        static::assertInstanceOf(Element::class, $placeholder);

        $keyInfo = $strategy->apply($document, $certificate);
        $signature->replaceChild($keyInfo, $placeholder);

        return $document;
    }

    private function document(string $token, string $keyInfo): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
            .' xmlns:wsse11="'.self::WSSE11.'"'
            .' xmlns:wsu="'.WsseSignatureFixture::WSU.'"'
            .' xmlns:ds="'.WsseSignatureFixture::DS.'">'
            .'<soap:Header><wsse:Security>'
            .$token
            .'<ds:Signature>'.$keyInfo.'</ds:Signature>'
            .'</wsse:Security></soap:Header>'
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

    private function base64Der(Certificate $certificate): string
    {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $certificate->contents());
        static::assertIsString($body);

        return $body;
    }
}
