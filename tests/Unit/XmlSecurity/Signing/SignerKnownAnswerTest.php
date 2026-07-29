<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Signing;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use VeeWee\Xml\Dom\Document;

/**
 * A known-answer vector: a fixed key signing a fixed document must reproduce the exact recorded bytes for
 * the canonical ds:SignedInfo, the ds:DigestValue and the ds:SignatureValue. Every input is pinned (preset
 * wsu:Id values, a hand-embedded token, no timestamp), so the whole pipeline is deterministic and any drift
 * in canonicalization, digesting or signing surfaces as a byte mismatch here — unlike the sign-then-verify
 * tests, which share the implementation between both sides and stay green through a symmetric bug.
 *
 * The pinned bytes were anchored independently when recorded: openssl verifies the SignatureValue over the
 * canonical SignedInfo bytes and reproduces the DigestValue from the canonical Body, and the WSS4J oracle
 * accepted an identically shaped envelope. Do not re-pin on a mismatch without that same evidence.
 */
#[RequiresPhp('>= 8.4.21')]
final class SignerKnownAnswerTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const X509_TOKEN = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';
    private const BASE64_BINARY = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary';

    private const EXPECTED_DIGEST_VALUE = 'XSXqMnE1ZXBj3TsiVtgZ6x6vS3k4JGhPcFjQYInjZMs=';
    private const EXPECTED_SIGNATURE_VALUE = 'Hu/d7b2apOUw7SsP9PgZQo3cpjFXX8IMuhwO1k1R6OgoKpI+iHfi8PKVjQnv8eGUJ+FrR25rd1Tg4xbGoIbf9yFhzb5ldc8eY+TtT2KE8RpkEFkH8yR/5+vPrL/PfMNpSZiKID6qIwPIFdU087z54ehkRabTsBSgOZkfKFLdODHyhk4F8z8lM8TEzw4snaGN5ERj21c2QIlxKPK3hbwUJsJxJqzULl64X0A+np53wAT/g9zKmCvMKBGH0Wh1bU43WyhRJ2/DQh2MXsJ/9E4a2PTDquRsNaPRpDjZVBKxkAAe0YKjSZpwI9BV6PdOW+8096WsTjpfi4P23TfTuIynyg==';

    public function test_a_fixed_key_over_a_fixed_document_reproduces_the_pinned_bytes(): void
    {
        $document = $this->fixedEnvelope();

        Signer::create(new WsuIdConvention())->sign($document, new SigningRequest(
            container: $this->security($document),
            targets: [Target::byId('Body-KAT')],
            signingKey: Key::fromFile(FIXTURE_DIR.'/interop/wss4j-recipient-php-client.key'),
            signingCertificate: Certificate::fromFile(FIXTURE_DIR.'/interop/wss4j-recipient-php-client.crt'),
            keyIdentifier: new DirectReferenceKeyIdentifier('SignedToken', self::X509_TOKEN),
            signatureMethod: SignatureMethod::RSA_SHA256,
            digestMethod: DigestMethod::SHA256,
            canonicalization: SignatureCanonicalization::EXC_C14N,
        ));

        // Read back from a fresh parse of the serialized document: the bytes a verifier receives.
        $wire = Document::fromXmlString($document->toXmlString())->toUnsafeDocument();

        $signedInfo = $wire->getElementsByTagNameNS(self::DS, 'SignedInfo')->item(0);
        static::assertInstanceOf(Element::class, $signedInfo);
        static::assertStringEqualsFile(
            FIXTURE_DIR.'/known-answer/signed-info.c14n',
            $signedInfo->C14N(true, false),
        );

        $digestValue = $wire->getElementsByTagNameNS(self::DS, 'DigestValue')->item(0);
        static::assertInstanceOf(Element::class, $digestValue);
        static::assertSame(self::EXPECTED_DIGEST_VALUE, $digestValue->textContent);

        $signatureValue = $wire->getElementsByTagNameNS(self::DS, 'SignatureValue')->item(0);
        static::assertInstanceOf(Element::class, $signatureValue);
        static::assertSame(self::EXPECTED_SIGNATURE_VALUE, $signatureValue->textContent);
    }

    /**
     * Every id is preset and the token is embedded by hand (mirroring the Outbound\BinarySecurityToken wire
     * shape), so no id minting happens during signing and the input is byte-identical on every run.
     */
    private function fixedEnvelope(): Document
    {
        $token = Certificate::fromFile(FIXTURE_DIR.'/interop/wss4j-recipient-php-client.crt')->toBase64Der();

        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.self::SOAP.'"'
            .' xmlns:wsse="'.self::WSSE.'"'
            .' xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header><wsse:Security>'
            .'<wsse:BinarySecurityToken'
            .' ValueType="'.self::X509_TOKEN.'"'
            .' EncodingType="'.self::BASE64_BINARY.'"'
            .' wsu:Id="SignedToken">'.$token.'</wsse:BinarySecurityToken>'
            .'</wsse:Security></soap:Header>'
            .'<soap:Body wsu:Id="Body-KAT"><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function security(Document $document): Element
    {
        $security = SecurityHeader::locate($document, SoapVersion::fromDocument($document));
        static::assertInstanceOf(Element::class, $security);

        return $security;
    }
}
