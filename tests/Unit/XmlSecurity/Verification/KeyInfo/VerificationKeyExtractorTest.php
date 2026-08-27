<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseKeyInfoResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\KeyInfoResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\VerificationKeyExtractor;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * Covers the inbound VerificationKeyExtractor: it reads the two forms that carry the certificate in the message (a
 * BST direct reference and an inline ds:X509Certificate), and resolves the three forms that name the certificate
 * by identifier (Subject Key Identifier, SHA-1 thumbprint, IssuerSerial) against the verifier's trust store. A
 * reference to a certificate the trust store does not hold is refused, and an ambiguous match is refused.
 *
 * The rejection cases assert the reason and not only the class. Every failure in here is one class by design, so
 * a class-only assertion passes on whichever check happens to fire -- which is how a refused ValueType and a
 * merely-unknown certificate become indistinguishable to the suite.
 */
final class VerificationKeyExtractorTest extends TestCase
{
    private const X509_TOKEN = WsseSignatureFixture::X509_TOKEN;
    private const WSSE11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
    private const THUMBPRINT_VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1';

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
        $this->expectExceptionMessage('The referenced security token was not found.');
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
        $this->expectExceptionMessage('The BinarySecurityToken value type is unsupported.');
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
        $this->expectExceptionMessage('The BinarySecurityToken encoding type is unsupported.');
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
        $document = $this->withKeyInfo(new X509SubjectKeyIdentifier($fixture->leafCertificate));

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
        $document = $this->withKeyInfo(new ThumbprintKeyIdentifier($fixture->leafCertificate));

        $chain = $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($this->base64Der($fixture->leafCertificate), $this->base64Der($chain->leaf()));
    }

    public function test_it_still_resolves_a_thumbprint_reference_in_the_1_1_namespace(): void
    {
        // KeyIdentifier is declared only in WSSE 1.0, so 1.0 is what this library emits. The 1.1 form is
        // tolerated on the way in: earlier releases emitted it, and any peer that made the same conflation
        // would otherwise be refused over a namespace that carries no meaning here.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $thumbprint = $fixture->leafCertificate->info()->thumbprintSha1()->toBase64();
        $document = $this->document('', '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse11:KeyIdentifier ValueType="'.self::THUMBPRINT_VALUE_TYPE.'">'.$thumbprint.'</wsse11:KeyIdentifier>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>');

        $chain = $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );

        static::assertSame($this->base64Der($fixture->leafCertificate), $this->base64Der($chain->leaf()));
    }

    public function test_it_refuses_a_key_identifier_whose_value_type_names_nothing_it_supports(): void
    {
        // Pinned at the document level on purpose. Only two identifier kinds can name a certificate here, and
        // which of them a reference carries is decided while reading ds:KeyInfo -- so an unknown ValueType has to
        // be refused from the message, not from whatever internal shape the reader happens to produce.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->document('', '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:KeyIdentifier ValueType="urn:not-a-key-identifier-we-know">anything</wsse:KeyIdentifier>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>');

        // The reason, not just the class: every failure in here is the same class by design, so a class-only
        // assertion passes whether the ValueType was refused or the identifier merely matched no anchor. Treating
        // an unknown ValueType as a Subject Key Identifier would still fail -- on "not known" -- and go unnoticed.
        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('The key identifier value type is unsupported.');
        $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );
    }

    public function test_a_reference_carrying_both_key_identifier_namespaces_is_refused(): void
    {
        // Tolerating the 1.1 form must not let a second KeyIdentifier shadow the real one.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $thumbprint = $fixture->leafCertificate->info()->thumbprintSha1()->toBase64();
        $identifier = '<%s:KeyIdentifier ValueType="'.self::THUMBPRINT_VALUE_TYPE.'">'.$thumbprint.'</%s:KeyIdentifier>';
        $document = $this->document('', '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .sprintf($identifier, 'wsse', 'wsse')
            .sprintf($identifier, 'wsse11', 'wsse11')
            .'</wsse:SecurityTokenReference></ds:KeyInfo>');

        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->caCertificate, $fixture->leafCertificate),
        );
    }

    public function test_it_resolves_a_signer_referenced_by_issuer_and_serial(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->withKeyInfo(new IssuerSerialKeyIdentifier($fixture->leafCertificate));

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
        $document = $this->withKeyInfo(new X509SubjectKeyIdentifier($fixture->leafCertificate));

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
        $document = $this->withKeyInfo(new X509SubjectKeyIdentifier($fixture->leafCertificate));

        // Two trust-store entries with the same identifier make the reference ambiguous.
        $this->expectException(SignatureVerificationFailed::class);
        $this->extractor()->extract(
            $document,
            $this->signature($document),
            TrustStore::fromCertificates($fixture->leafCertificate, $fixture->leafCertificate),
        );
    }

    public function test_an_unrecognised_token_reference_does_not_fall_through_to_a_certificate_beside_it(): void
    {
        // The one shape whose handling changed when the WS-Security forms moved out of the engine, so it is pinned
        // here rather than left to be re-derived. A token reference says which key signed. If it names nothing this
        // profile defines, the answer is refusal -- not the inline certificate sitting next to it, which is a
        // different key than the sender pointed at. The old reader fell through to that sibling and verified.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $base64Der = $fixture->certificateBase64Der($fixture->leafCertificate);
        $document = $this->document('', '<ds:KeyInfo>'
            .'<wsse:SecurityTokenReference/>'
            .'<ds:X509Data><ds:X509Certificate>'.$base64Der.'</ds:X509Certificate></ds:X509Data>'
            .'</ds:KeyInfo>');

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('ds:KeyInfo does not carry the certificate in a supported form.');
        $this->extractor()->extract($document, $this->signature($document), TrustStore::fromCertificates());
    }

    public function test_a_resolver_that_throws_anything_else_still_fails_as_one_verification_failure(): void
    {
        // The resolver is a replaceable seam, so a third-party one can raise a type of its own. If that escaped,
        // a peer could tell from the exception which shape of ds:KeyInfo its message failed on -- exactly the
        // difference the uniform fault exists to deny. The cause stays available for the operator log.
        $hostile = new class implements KeyInfoResolver {
            public function read(Document $document, Element $signatureElement, IdLookup $idLookup): CertificateReference
            {
                throw new RuntimeException('resolver-detail-text');
            }
        };
        $document = $this->document('', '<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>');

        try {
            (new VerificationKeyExtractor($hostile, (new WsuIdConvention())->lookup()))
                ->extract($document, $this->signature($document), TrustStore::fromCertificates());
            static::fail('The hostile resolver was expected to be refused.');
        } catch (SignatureVerificationFailed $failure) {
            static::assertStringNotContainsString('resolver-detail-text', $failure->getMessage());
            static::assertInstanceOf(RuntimeException::class, $failure->getPrevious());
            static::assertSame('resolver-detail-text', $failure->getPrevious()->getMessage());
        }
    }

    private function extractor(): VerificationKeyExtractor
    {
        return new VerificationKeyExtractor(new WsseKeyInfoResolver(), (new WsuIdConvention())->lookup());
    }

    /**
     * Builds an envelope whose ds:Signature carries a ds:KeyInfo produced by the given outbound key-identifier
     * strategy for the given certificate, the form a conformant peer emits when it names the signer by identifier.
     */
    private function withKeyInfo(KeyIdentifier $strategy): Document
    {
        $document = $this->document('', '<ds:KeyInfoPlaceholder/>');
        $native = $document->toUnsafeDocument();

        $signature = $native->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);
        $placeholder = $native->getElementsByTagNameNS(WsseSignatureFixture::DS, 'KeyInfoPlaceholder')->item(0);
        static::assertInstanceOf(Element::class, $placeholder);

        $keyInfo = $strategy->apply($document);
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
