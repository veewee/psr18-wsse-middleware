<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use VeeWee\Xml\Dom\Document;

/**
 * Verifies a real Apache WSS4J signed message. WSS4J emits an exclusive-c14n InclusiveNamespaces PrefixList on
 * the CanonicalizationMethod and on each reference Transform; the verifier must honour those prefixes when it
 * re-canonicalizes, otherwise the recomputed bytes (and digests) differ from what was signed.
 */
#[RequiresPhp('>= 8.4.21')]
final class Wss4jInteropTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_it_verifies_a_real_wss4j_signed_message(): void
    {
        $document = Document::fromXmlString((string) file_get_contents(
            FIXTURE_DIR.'/interop/wss4j-signed.xml',
        ));

        $result = Verifier::create((new WsuIdConvention())->lookup())->verify($document, $this->policy(), $this->security($document));

        static::assertInstanceOf(VerifiedSignature::class, $result);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertTrue($result->signedElements->wasSigned($this->timestamp($document)));
        static::assertStringContainsString('java-server', $result->signer->subjectDistinguishedName()->toString());
    }

    public function test_it_verifies_a_real_wss4j_ecdsa_signed_message(): void
    {
        $document = Document::fromXmlString((string) file_get_contents(
            FIXTURE_DIR.'/interop/wss4j-signed-ecdsa.xml',
        ));

        $result = Verifier::create((new WsuIdConvention())->lookup())->verify($document, $this->ecdsaPolicy(), $this->security($document));

        static::assertInstanceOf(VerifiedSignature::class, $result);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertStringContainsString('ec client', $result->signer->subjectDistinguishedName()->toString());
    }

    private function ecdsaPolicy(): VerificationPolicy
    {
        return new VerificationPolicy(
            trustStore: TrustStore::fromCertificates(
                Certificate::fromFile(FIXTURE_DIR.'/interop/wss4j-ca.crt'),
            ),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::ECDSA_SHA256],
                acceptedDigestMethods: [DigestMethod::SHA256],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        );
    }

    public function test_it_verifies_a_real_wss4j_inclusive_c14n_signed_message(): void
    {
        // WSS4J applies the inclusive canonicalization to ds:SignedInfo while keeping exclusive transforms on
        // each reference, so the message is mixed: the policy must accept both for the verification to pass.
        $document = Document::fromXmlString((string) file_get_contents(
            FIXTURE_DIR.'/interop/wss4j-signed-inclusive-c14n.xml',
        ));

        $result = Verifier::create((new WsuIdConvention())->lookup())->verify($document, $this->inclusiveC14nPolicy(), $this->security($document));

        static::assertInstanceOf(VerifiedSignature::class, $result);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertStringContainsString('java-server', $result->signer->subjectDistinguishedName()->toString());
    }

    private function inclusiveC14nPolicy(): VerificationPolicy
    {
        return new VerificationPolicy(
            trustStore: TrustStore::fromCertificates(
                Certificate::fromFile(FIXTURE_DIR.'/interop/wss4j-ca.crt'),
            ),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
                acceptedDigestMethods: [DigestMethod::SHA256],
                acceptedCanonicalizations: [SignatureCanonicalization::C14N, SignatureCanonicalization::EXC_C14N],
            ),
        );
    }

    private function policy(): VerificationPolicy
    {
        return new VerificationPolicy(
            trustStore: TrustStore::fromCertificates(
                Certificate::fromFile(FIXTURE_DIR.'/interop/wss4j-ca.crt'),
            ),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
                acceptedDigestMethods: [DigestMethod::SHA256],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        );
    }

    /**
     * The Security header addressed to the ultimate receiver, which is the scope the WSSE block resolves and
     * hands the verifier.
     */
    private function security(Document $document): Element
    {
        return SecurityHeader::locate($document, SoapVersion::fromDocument($document))
            ?? throw new RuntimeException('The fixture carries no Security header for the ultimate receiver.');
    }

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }

    private function timestamp(Document $document): Element
    {
        $timestamp = $document->toUnsafeDocument()->getElementsByTagNameNS(self::WSU, 'Timestamp')->item(0);
        static::assertInstanceOf(Element::class, $timestamp);

        return $timestamp;
    }
}
