<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\X509DataKeyInfoResolver;
use VeeWee\Xml\Dom\Document;

/**
 * The engine's own default KeyInfo resolver, which is what makes the layer drivable on plain XML-DSig without
 * the WS-Security profile. Every in-tree caller overrides it with the profile's resolver, so nothing else
 * exercises it directly and its multi-certificate form is reached by nothing at all.
 *
 * That form is the one worth pinning: a peer carrying its whole certification path as sibling
 * ds:X509Certificate elements is spec-legal, and a reader that dropped one, reordered them, or picked the
 * wrong element as the end-entity would produce a chain nothing else in the suite would notice.
 */
final class X509DataKeyInfoResolverTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_it_reads_a_single_inline_certificate(): void
    {
        $reference = $this->read($this->keyInfo('<ds:X509Data><ds:X509Certificate>Y2VydC1vbmU=</ds:X509Certificate></ds:X509Data>'));

        static::assertSame(CertificateReference::FORM_CARRIED, $reference->form);
        static::assertSame(['Y2VydC1vbmU='], $reference->base64DerCertificates);
    }

    public function test_it_reads_a_certification_path_in_document_order(): void
    {
        // Document order, not sorted or de-duplicated: which of these is the end-entity is decided later from
        // issuer linkage, so reordering here would silently change which certificate a chain is built around.
        $reference = $this->read($this->keyInfo(
            '<ds:X509Data>'
            .'<ds:X509Certificate>bGVhZg==</ds:X509Certificate>'
            .'<ds:X509Certificate>aW50ZXJtZWRpYXRl</ds:X509Certificate>'
            .'<ds:X509Certificate>cm9vdA==</ds:X509Certificate>'
            .'</ds:X509Data>',
        ));

        static::assertSame(CertificateReference::FORM_CARRIED, $reference->form);
        static::assertSame(['bGVhZg==', 'aW50ZXJtZWRpYXRl', 'cm9vdA=='], $reference->base64DerCertificates);
    }

    public function test_whitespace_around_a_certificate_is_not_part_of_it(): void
    {
        // A peer may pretty-print the element; the surrounding whitespace is not base64 and must not reach the
        // decoder, which would otherwise refuse a perfectly ordinary message.
        $reference = $this->read($this->keyInfo(
            "<ds:X509Data><ds:X509Certificate>\n  Y2VydC1vbmU=\n  </ds:X509Certificate></ds:X509Data>",
        ));

        static::assertSame(['Y2VydC1vbmU='], $reference->base64DerCertificates);
    }

    public function test_a_missing_key_info_is_refused(): void
    {
        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('ds:KeyInfo is missing.');

        $this->read($this->signatureWithout());
    }

    public function test_a_key_info_carrying_no_inline_certificate_is_refused(): void
    {
        // A shape the engine does not model on its own, such as a WS-Security token reference. It is refused
        // rather than read as empty, which is what lets the profile inject a resolver that does understand it.
        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('does not carry the certificate in a supported form');

        $this->read($this->keyInfo('<ds:X509Data><ds:X509SubjectName>CN=peer</ds:X509SubjectName></ds:X509Data>'));
    }

    public function test_a_second_x509_data_cannot_shadow_the_first(): void
    {
        // Refused outright rather than one being picked, so an injected sibling cannot decide which
        // certificate the signature is checked against.
        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('X509Data must appear at most once');

        $this->read($this->keyInfo(
            '<ds:X509Data><ds:X509Certificate>cmVhbA==</ds:X509Certificate></ds:X509Data>'
            .'<ds:X509Data><ds:X509Certificate>aW5qZWN0ZWQ=</ds:X509Certificate></ds:X509Data>',
        ));
    }

    private function read(string $xml): CertificateReference
    {
        $document = Document::fromXmlString($xml);
        $signature = $document->toUnsafeDocument()->getElementsByTagNameNS(self::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        return (new X509DataKeyInfoResolver())->read(
            $document,
            $signature,
            AttributeIdConvention::xmlId()->lookup(),
        );
    }

    private function keyInfo(string $children): string
    {
        return '<ds:Signature xmlns:ds="'.self::DS.'"><ds:KeyInfo>'.$children.'</ds:KeyInfo></ds:Signature>';
    }

    private function signatureWithout(): string
    {
        return '<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignatureValue>ZmlsbGVy</ds:SignatureValue></ds:Signature>';
    }
}
