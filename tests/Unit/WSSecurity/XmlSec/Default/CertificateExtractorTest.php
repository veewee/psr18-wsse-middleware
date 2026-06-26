<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default\CertificateExtractor;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

final class CertificateExtractorTest extends TestCase
{
    private const X509_TOKEN = WsseSignatureFixture::X509_TOKEN;

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

        $chain = (new CertificateExtractor())->extract($document, $this->signature($document));

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

        $chain = (new CertificateExtractor())->extract($document, $this->signature($document));

        static::assertStringContainsString('CERTIFICATE', $chain->leaf()->contents());
    }

    public function test_it_rejects_a_missing_key_info(): void
    {
        $document = $this->document('', '');

        $this->expectException(SignatureVerificationFailed::class);
        (new CertificateExtractor())->extract($document, $this->signature($document));
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
        (new CertificateExtractor())->extract($document, $this->signature($document));
    }

    public function test_it_rejects_a_certificate_named_by_identifier(): void
    {
        // A SecurityTokenReference > KeyIdentifier (SKI / thumbprint) names the cert without carrying it.
        $document = $this->document(
            '',
            '<ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1">'
            .base64_encode('thumbprint').'</wsse:KeyIdentifier>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo>'
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new CertificateExtractor())->extract($document, $this->signature($document));
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
        (new CertificateExtractor())->extract($document, $this->signature($document));
    }

    private function document(string $token, string $keyInfo): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
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
}
