<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Default;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SigningFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\KeyInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

/**
 * Asserts the Signer emits the expected ds:Signature structure: the right references, reused wsu:Id values,
 * canonical header ordering, and a byte-stable body digest.
 */
#[RequiresPhp('>= 8.4.21')]
final class SignerTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const X509_TOKEN = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    public function test_it_signs_the_body(): void
    {
        [, , $document] = $this->sign([Target::element(self::SOAP, 'Body')]);

        $references = $this->references($document);
        static::assertCount(1, $references);
        static::assertSame('#'.$this->bodyId($document), $references[0]->getAttribute('URI'));
    }

    public function test_it_signs_the_timestamp(): void
    {
        [, , $document] = $this->sign([Target::element(self::WSU, 'Timestamp')], withTimestamp: true);

        static::assertCount(1, $this->references($document));
    }

    public function test_it_signs_the_body_and_the_timestamp_with_two_references(): void
    {
        [, , $document] = $this->sign([Target::element(self::SOAP, 'Body'), Target::element(self::WSU, 'Timestamp')], withTimestamp: true);

        static::assertCount(2, $this->references($document));
    }

    public function test_it_signs_a_specific_header_element(): void
    {
        [, , $document] = $this->sign([Target::element('urn:app', 'Custom')], withCustom: true);

        static::assertCount(1, $this->references($document));
    }

    public function test_it_reuses_an_existing_wsu_id(): void
    {
        [, , $document] = $this->sign([Target::byId('Body-Preset')], presetBodyId: 'Body-Preset');

        static::assertSame('#Body-Preset', $this->references($document)[0]->getAttribute('URI'));
    }

    public function test_it_emits_the_signature_structure(): void
    {
        [, , $document] = $this->sign([Target::element(self::SOAP, 'Body')]);

        $signature = $this->signature($document);
        static::assertNotNull($this->child($signature, 'SignedInfo'));
        static::assertNotNull($this->child($signature, 'SignatureValue'));
        static::assertNotNull($this->child($signature, 'KeyInfo'));
    }

    public function test_the_signature_is_appended_to_the_security_header_in_canonical_order(): void
    {
        [, , $document] = $this->sign([Target::element(self::SOAP, 'Body')], withTimestamp: true);

        $security = $document->toUnsafeDocument()->getElementsByTagNameNS(self::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $security);

        $order = [];
        foreach ($security->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        // Timestamp precedes Signature in the WS-Security canonical order.
        static::assertSame(['Timestamp', 'Signature'], $order);
    }

    public function test_it_throws_when_no_security_header_exists(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Header/><soap:Body><data>x</data></soap:Body></soap:Envelope>'
        );

        $this->expectException(SigningFailed::class);
        $this->signer()->sign($document, $this->request([Target::element(self::SOAP, 'Body')], $key, $certificate));
    }

    public function test_it_signs_the_parts_not_an_existing_signature(): void
    {
        // A pre-existing ds:Signature must never become a signed target: only the Body is referenced. The
        // body id is referenced, never the signature element, so signing the signature itself is impossible.
        [, , $document] = $this->sign([Target::element(self::SOAP, 'Body')], withStaleSignature: true);

        $references = $this->references($document);
        static::assertSame('#'.$this->bodyId($document), $references[0]->getAttribute('URI'));
        foreach ($references as $reference) {
            static::assertStringNotContainsString('Signature', (string) $reference->getAttribute('URI'));
        }
    }

    public function test_the_body_digest_is_byte_stable_for_rsa_sha256(): void
    {
        [, , $document] = $this->sign([Target::element(self::SOAP, 'Body')]);

        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        $expected = base64_encode(hash('sha256', $body->C14N(true, false), true));
        $digestValue = $this->child($this->references($document)[0], 'DigestValue');
        static::assertNotNull($digestValue);
        static::assertSame($expected, $digestValue->textContent);
    }

    /**
     * @param non-empty-list<Target> $targets
     *
     * @return array{0: Key, 1: Certificate, 2: Document}
     */
    private function sign(
        array $targets,
        bool $withTimestamp = false,
        bool $withCustom = false,
        bool $withStaleSignature = false,
        ?string $presetBodyId = null,
    ): array {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope($withTimestamp, $withCustom, $withStaleSignature, $presetBodyId);

        $this->signer()->sign($document, $this->request($targets, $key, $certificate));

        return [$key, $certificate, $document];
    }

    /**
     * @param non-empty-list<Target> $targets
     */
    private function request(array $targets, Key $key, Certificate $certificate): SigningRequest
    {
        return new SigningRequest(
            targets: $targets,
            signingKey: $key,
            signingCertificate: $certificate,
            keyIdentifier: new DirectReferenceKeyIdentifier('SignedToken', self::X509_TOKEN),
            signatureMethod: SignatureMethod::RSA_SHA256,
            digestMethod: DigestMethod::SHA256,
            canonicalization: SignatureCanonicalization::EXC_C14N,
        );
    }

    private function signer(): Signer
    {
        $canonicalizer = new DomCanonicalizer();

        return new Signer(
            new ReferenceCollector(new WsuIdMinter(), new TargetLocator()),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            new KeyInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
        );
    }

    private function envelope(bool $withTimestamp, bool $withCustom, bool $withStaleSignature, ?string $presetBodyId): Document
    {
        $bodyId = $presetBodyId !== null ? ' wsu:Id="'.$presetBodyId.'"' : '';
        $timestamp = $withTimestamp ? '<wsu:Timestamp><wsu:Created>2026-01-01T00:00:00Z</wsu:Created></wsu:Timestamp>' : '';
        $stale = $withStaleSignature ? '<ds:Signature><ds:SignatureValue>stale</ds:SignatureValue></ds:Signature>' : '';
        $custom = $withCustom ? '<app:Custom xmlns:app="urn:app">payload</app:Custom>' : '';

        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.self::SOAP.'"'
            .' xmlns:wsse="'.self::WSSE.'"'
            .' xmlns:wsu="'.self::WSU.'"'
            .' xmlns:ds="'.self::DS.'">'
            .'<soap:Header><wsse:Security>'.$timestamp.$stale.'</wsse:Security>'.$custom.'</soap:Header>'
            .'<soap:Body'.$bodyId.'><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    /**
     * @return list<Element>
     */
    private function references(Document $document): array
    {
        $signedInfo = $this->child($this->signature($document), 'SignedInfo');
        static::assertInstanceOf(Element::class, $signedInfo);

        $references = [];
        foreach ($signedInfo->childNodes as $child) {
            if ($child instanceof Element && $child->localName === 'Reference') {
                $references[] = $child;
            }
        }

        return $references;
    }

    private function signature(Document $document): Element
    {
        // Pick the real signature (the one carrying a ds:SignedInfo), not any stale placeholder in a fixture.
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::DS, 'Signature') as $candidate) {
            if ($candidate instanceof Element && $this->child($candidate, 'SignedInfo') !== null) {
                return $candidate;
            }
        }

        static::fail('No signed ds:Signature element found.');
    }

    private function bodyId(Document $document): string
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body->getAttributeNS(self::WSU, 'Id');
    }

    private function child(Element $element, string $localName): ?Element
    {
        foreach ($element->childNodes as $child) {
            if ($child instanceof Element && $child->localName === $localName) {
                return $child;
            }
        }

        return null;
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function keyAndCertificate(): array
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => 'wsse-signer-test'], $private);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return [new Key($privatePem), new Certificate($certificatePem)];
    }
}
