<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use VeeWee\Xml\Dom\Document;

/**
 * A ds:Reference that declares no ds:Transforms is digested under inclusive c14n, the XML-DSig default for a
 * node-set with no transform. That default is an algorithm choice like any other, so it has to clear the
 * policy allow-list: these pin that the exclusive-only default refuses it and that opting inclusive c14n in
 * is what makes it verifiable, rather than the parser quietly deciding either way on the caller's behalf.
 */
final class AlgorithmPolicyEnforcerTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    private const SHA256_DIGEST = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

    public function test_the_exclusive_only_default_refuses_a_transform_less_reference(): void
    {
        $signedInfo = (new SignedInfoParser())->parse($this->signatureWithoutTransforms());

        $this->expectException(SignatureVerificationFailed::class);
        (new AlgorithmPolicyEnforcer())->enforce(
            $this->policy(SignatureCanonicalization::EXC_C14N, SignatureCanonicalization::EXC_C14N_COMMENTS),
            $signedInfo,
        );
    }

    public function test_opting_inclusive_c14n_in_accepts_a_transform_less_reference(): void
    {
        $signedInfo = (new SignedInfoParser())->parse($this->signatureWithoutTransforms());

        (new AlgorithmPolicyEnforcer())->enforce(
            $this->policy(SignatureCanonicalization::EXC_C14N, SignatureCanonicalization::C14N),
            $signedInfo,
        );

        static::assertSame(SignatureCanonicalization::C14N, $signedInfo->references[0]->canonicalization);
    }

    private function policy(SignatureCanonicalization ...$accepted): VerificationPolicy
    {
        return new VerificationPolicy(
            TrustStore::fromCertificates(),
            [SignatureMethod::RSA_SHA256],
            [DigestMethod::SHA256],
            $accepted,
        );
    }

    private function signatureWithoutTransforms(): Element
    {
        $document = Document::fromXmlString(
            '<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignedInfo>'
            .'<ds:CanonicalizationMethod Algorithm="'.self::EXC_C14N.'"/>'
            .'<ds:SignatureMethod Algorithm="'.self::RSA_SHA256.'"/>'
            .'<ds:Reference URI="#Body">'
            .'<ds:DigestMethod Algorithm="'.self::SHA256_DIGEST.'"/>'
            .'<ds:DigestValue>'.base64_encode('digest').'</ds:DigestValue>'
            .'</ds:Reference>'
            .'</ds:SignedInfo></ds:Signature>',
        );

        $signature = $document->toUnsafeDocument()->getElementsByTagNameNS(self::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        return $signature;
    }
}
