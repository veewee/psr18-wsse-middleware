<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\SignatureValidator;
use SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

#[RequiresPhp('>= 8.4.21')]
final class SignatureValidatorTest extends TestCase
{
    public function test_it_returns_true_for_a_valid_signature(): void
    {
        [$signature, $certificate] = $this->signed();

        static::assertTrue($this->validator()->validate(
            $signature,
            $certificate,
            SignatureMethod::RSA_SHA256,
            SignatureCanonicalization::EXC_C14N,
            [],
        ));
    }

    public function test_it_returns_false_for_a_tampered_signature_value(): void
    {
        [$signature, $certificate] = $this->signed();

        $value = $this->child($signature, 'SignatureValue');
        $value->textContent = base64_encode('forged-bytes');

        static::assertFalse($this->validator()->validate(
            $signature,
            $certificate,
            SignatureMethod::RSA_SHA256,
            SignatureCanonicalization::EXC_C14N,
            [],
        ));
    }

    public function test_it_rejects_an_absent_signed_info(): void
    {
        [$signature, $certificate] = $this->signed();
        $signature->removeChild($this->child($signature, 'SignedInfo'));

        $this->expectException(SignatureVerificationFailed::class);
        $this->validator()->validate($signature, $certificate, SignatureMethod::RSA_SHA256, SignatureCanonicalization::EXC_C14N, []);
    }

    public function test_it_rejects_two_signed_info_children(): void
    {
        [$signature, $certificate] = $this->signed();
        $signature->appendChild($this->child($signature, 'SignedInfo')->cloneNode(true));

        $this->expectException(SignatureVerificationFailed::class);
        $this->validator()->validate($signature, $certificate, SignatureMethod::RSA_SHA256, SignatureCanonicalization::EXC_C14N, []);
    }

    public function test_it_rejects_a_signature_value_before_the_signed_info(): void
    {
        [$signature, $certificate] = $this->signed();

        $signedInfo = $this->child($signature, 'SignedInfo');
        $value = $this->child($signature, 'SignatureValue');
        // Move the SignatureValue ahead of the SignedInfo.
        $signature->insertBefore($value, $signedInfo);

        $this->expectException(SignatureVerificationFailed::class);
        $this->validator()->validate($signature, $certificate, SignatureMethod::RSA_SHA256, SignatureCanonicalization::EXC_C14N, []);
    }

    public function test_it_rejects_an_absent_key_info(): void
    {
        [$signature, $certificate] = $this->signed();
        $signature->removeChild($this->child($signature, 'KeyInfo'));

        $this->expectException(SignatureVerificationFailed::class);
        $this->validator()->validate($signature, $certificate, SignatureMethod::RSA_SHA256, SignatureCanonicalization::EXC_C14N, []);
    }

    private function validator(): SignatureValidator
    {
        return new SignatureValidator(new DomCanonicalizer(), new OpenSslSigner());
    }

    /**
     * @return array{0: Element, 1: Certificate}
     */
    private function signed(): array
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([Part::body()]);

        return [$this->signature($document), $fixture->leafCertificate];
    }

    private function signature(Document $document): Element
    {
        $signature = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        return $signature;
    }

    private function child(Element $parent, string $localName): Element
    {
        foreach ($parent->childNodes as $child) {
            if ($child instanceof Element && $child->localName === $localName) {
                return $child;
            }
        }

        static::fail(sprintf('No ds:%s child found.', $localName));
    }
}
