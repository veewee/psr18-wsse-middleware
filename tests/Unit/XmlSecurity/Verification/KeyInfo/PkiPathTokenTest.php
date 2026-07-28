<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\WsSecurityValueType;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * A wsse:BinarySecurityToken may carry a whole certification path as a PKIPath rather than a single
 * certificate, which the X.509 Token Profile recommends over a PKCS#7 wrapper. Such a token was refused as an
 * unsupported value type, so a peer configured to send its path could not be verified at all.
 *
 * The path's own order is not trusted: the end-entity is derived from issuer linkage, which is what makes this
 * correct whichever direction the sender used.
 */
final class PkiPathTokenTest extends TestCase
{
    public function test_it_reads_a_certification_path_from_a_pkipath_token(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // The CA first, the end-entity last.
        $path = $this->pkiPath(
            $fixture->certificateBase64Der($fixture->caCertificate),
            $fixture->certificateBase64Der($fixture->leafCertificate),
        );

        $chain = $this->extract($this->document(WsSecurityValueType::X509PKIPathv1->value, $path));

        static::assertCount(2, $chain->all());
        static::assertStringContainsString('WSSE Round Trip Leaf', $chain->leaf()->info()->subject()->toString());
        static::assertNotNull($chain->intermediatesPem());
    }

    public function test_the_end_entity_is_derived_whichever_direction_the_path_uses(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        // The same path reversed: end-entity first.
        $path = $this->pkiPath(
            $fixture->certificateBase64Der($fixture->leafCertificate),
            $fixture->certificateBase64Der($fixture->caCertificate),
        );

        $chain = $this->extract($this->document(WsSecurityValueType::X509PKIPathv1->value, $path));

        static::assertStringContainsString('WSSE Round Trip Leaf', $chain->leaf()->info()->subject()->toString());
    }

    public function test_a_pkipath_token_that_is_not_a_sequence_is_refused(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->extract($this->document(WsSecurityValueType::X509PKIPathv1->value, base64_encode('not-der')));
    }

    public function test_a_single_certificate_token_is_still_read_as_one_certificate(): void
    {
        // The X509v3 body is a bare certificate, not a path, so it must not be run through the path parser.
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->document(
            WsSecurityValueType::X509v3->value,
            $fixture->certificateBase64Der($fixture->leafCertificate),
        );

        $chain = $this->extract($document);

        static::assertCount(1, $chain->all());
        static::assertStringContainsString('WSSE Round Trip Leaf', $chain->leaf()->info()->subject()->toString());
    }

    private function extract(Document $document): \Soap\Psr18WsseMiddleware\KeyStore\CertificateChain
    {
        return (new CertificateExtractor(new WsuIdLookup()))
            ->extract($document, $this->signature($document), TrustStore::fromCertificates());
    }

    /**
     * Wraps the given base64-DER certificates in an ASN.1 SEQUENCE and returns it base64-encoded, the form a
     * PKIPath token body takes. The length is encoded by hand so the fixture never depends on the parser.
     */
    private function pkiPath(string ...$base64Der): string
    {
        $body = '';
        foreach ($base64Der as $certificate) {
            $body .= (string) base64_decode($certificate, true);
        }

        $length = strlen($body);
        if ($length < 0x80) {
            $header = chr($length);
        } else {
            $bytes = '';
            for ($remaining = $length; $remaining > 0; $remaining >>= 8) {
                $bytes = chr($remaining & 0xFF).$bytes;
            }
            $header = chr(0x80 | strlen($bytes)).$bytes;
        }

        return base64_encode("\x30".$header.$body);
    }

    private function document(string $valueType, string $tokenBody): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
            .' xmlns:wsu="'.WsseSignatureFixture::WSU.'"'
            .' xmlns:ds="'.WsseSignatureFixture::DS.'">'
            .'<soap:Header><wsse:Security>'
            .'<wsse:BinarySecurityToken wsu:Id="SignedToken" ValueType="'.$valueType.'">'.$tokenBody.'</wsse:BinarySecurityToken>'
            .'<ds:Signature><ds:KeyInfo><wsse:SecurityTokenReference>'
            .'<wsse:Reference URI="#SignedToken"/>'
            .'</wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature>'
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
