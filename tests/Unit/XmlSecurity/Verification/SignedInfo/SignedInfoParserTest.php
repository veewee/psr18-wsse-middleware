<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use VeeWee\Xml\Dom\Document;

final class SignedInfoParserTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const EC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const SHA256_DIGEST = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    public function test_it_reads_the_canonicalization_prefix_list(): void
    {
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'">'
                .'<ec:InclusiveNamespaces xmlns:ec="'.self::EC.'" PrefixList="soap wsse"/>'
                .'</ds:CanonicalizationMethod>',
            references: $this->reference('#Body', self::EXC_C14N, null),
        );

        $parsed = (new SignedInfoParser())->parse($signedInfo);

        static::assertSame(['soap', 'wsse'], $parsed->canonicalizationInclusivePrefixes);
    }

    public function test_an_absent_canonicalization_prefix_list_is_empty(): void
    {
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $this->reference('#Body', self::EXC_C14N, null),
        );

        $parsed = (new SignedInfoParser())->parse($signedInfo);

        static::assertSame([], $parsed->canonicalizationInclusivePrefixes);
    }

    public function test_it_reads_a_reference_transform_prefix_list(): void
    {
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $this->reference('#Body', self::EXC_C14N, 'wsse soap'),
        );

        $parsed = (new SignedInfoParser())->parse($signedInfo);

        static::assertSame(SignatureCanonicalization::EXC_C14N, $parsed->references[0]->canonicalization);
        static::assertSame(['wsse', 'soap'], $parsed->references[0]->inclusivePrefixes);
    }

    public function test_a_reference_transform_without_a_prefix_list_is_empty(): void
    {
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $this->reference('#Body', self::EXC_C14N, null),
        );

        $parsed = (new SignedInfoParser())->parse($signedInfo);

        static::assertSame(SignatureCanonicalization::EXC_C14N, $parsed->references[0]->canonicalization);
        static::assertSame([], $parsed->references[0]->inclusivePrefixes);
    }

    public function test_it_rejects_a_non_canonicalization_reference_transform(): void
    {
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $this->reference('#Body', 'http://www.w3.org/TR/1999/REC-xslt-19991116', null),
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new SignedInfoParser())->parse($signedInfo);
    }

    public function test_it_parses_an_inclusive_c14n_reference_transform(): void
    {
        // The parser only structurally reads the transform; whether an inclusive c14n is accepted is decided
        // later by the policy enforcer, not here.
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $this->reference('#Body', SignatureCanonicalization::C14N->value, null),
        );

        $parsed = (new SignedInfoParser())->parse($signedInfo);

        static::assertSame(SignatureCanonicalization::C14N, $parsed->references[0]->canonicalization);
        static::assertSame([], $parsed->references[0]->inclusivePrefixes);
    }

    public function test_it_rejects_an_unknown_reference_transform(): void
    {
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $this->reference('#Body', 'urn:not-a-canonicalization', null),
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new SignedInfoParser())->parse($signedInfo);
    }

    public function test_it_rejects_more_than_one_reference_transform(): void
    {
        $reference = '<ds:Reference URI="#Body"><ds:Transforms>'
            .'<ds:Transform Algorithm="'.self::EXC_C14N.'"/>'
            .'<ds:Transform Algorithm="'.self::EXC_C14N.'"/>'
            .'</ds:Transforms>'
            .'<ds:DigestMethod Algorithm="'.self::SHA256_DIGEST.'"/>'
            .'<ds:DigestValue>'.base64_encode('digest').'</ds:DigestValue>'
            .'</ds:Reference>';

        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $reference,
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new SignedInfoParser())->parse($signedInfo);
    }

    public function test_an_hmac_signature_method_is_refused(): void
    {
        // HMAC is symmetric: accepting it would let a peer that knows or can guess the shared secret forge a
        // signature this library would then report as valid. No HMAC URI is representable, so substituting one
        // resolves to nothing -- this pins that, so adding HMAC to the enum for parity cannot quietly admit it.
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: $this->reference('#Body', self::EXC_C14N, null),
            signatureMethod: '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>',
        );

        $this->expectException(SignatureVerificationFailed::class);
        (new SignedInfoParser())->parse($signedInfo);
    }

    public function test_a_reference_without_transforms_digests_under_inclusive_c14n(): void
    {
        // XML-DSig converts a node-set to octets with Canonical XML when no transform says otherwise, so a
        // reference that declares no ds:Transforms is digested under inclusive c14n, not under whatever
        // SignedInfo happens to declare for itself.
        $signedInfo = $this->signedInfo(
            canonicalization: '<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>',
            references: '<ds:Reference URI="#Body">'
                .'<ds:DigestMethod Algorithm="'.self::SHA256_DIGEST.'"/>'
                .'<ds:DigestValue>'.base64_encode('digest').'</ds:DigestValue>'
                .'</ds:Reference>',
        );

        $parsed = (new SignedInfoParser())->parse($signedInfo);

        static::assertSame(SignatureCanonicalization::C14N, $parsed->references[0]->canonicalization);
        static::assertSame([], $parsed->references[0]->inclusivePrefixes);
    }

    private function reference(string $uri, string $transform, ?string $prefixList): string
    {
        $inclusive = $prefixList !== null
            ? '<ec:InclusiveNamespaces xmlns:ec="'.self::EC.'" PrefixList="'.$prefixList.'"/>'
            : '';

        return '<ds:Reference URI="'.$uri.'">'
            .'<ds:Transforms><ds:Transform Algorithm="'.$transform.'">'.$inclusive.'</ds:Transform></ds:Transforms>'
            .'<ds:DigestMethod Algorithm="'.self::SHA256_DIGEST.'"/>'
            .'<ds:DigestValue>'.base64_encode('digest').'</ds:DigestValue>'
            .'</ds:Reference>';
    }

    private function signedInfo(string $canonicalization, string $references, ?string $signatureMethod = null): Element
    {
        $document = Document::fromXmlString(
            '<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignedInfo>'
            .$canonicalization
            .($signatureMethod ?? '<ds:SignatureMethod Algorithm="'.self::RSA_SHA256.'"/>')
            .$references
            .'</ds:SignedInfo></ds:Signature>',
        );

        $signature = $document->toUnsafeDocument()->getElementsByTagNameNS(self::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        return $signature;
    }
}
