<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionMode;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionTarget;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalEncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalPartSealer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

/**
 * The strong proof of the inbound Decrypt block through the real OpenSSL\ path: a Body encrypted by the
 * engine's Encryptor is recovered to its original plaintext, and every decryption failure cause (wrong key,
 * tampered ciphertext, missing EncryptedKey) surfaces as one identical SecurityFault. No discriminator may
 * leak through the inbound boundary, so the engine is never a padding or validation oracle.
 */
final class DecryptRoundTripTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const X509_TOKEN = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    public function test_it_recovers_the_original_body(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $originalBody = $this->innerXml($this->body($document));

        $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));
        static::assertCount(1, $this->encryptedData($document));

        (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));

        static::assertSame($originalBody, $this->innerXml($this->body($document)));
        static::assertCount(0, $this->encryptedData($document));
    }

    public function test_it_recovers_a_body_whose_encrypted_data_carries_a_native_id(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $originalBody = $this->innerXml($this->body($document));

        $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));

        // Relabel the minted wsu:Id to a native, namespace-less @Id, as some interop peers emit.
        $this->relabelToNativeId($document);

        (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));

        static::assertSame($originalBody, $this->innerXml($this->body($document)));
        static::assertCount(0, $this->encryptedData($document));
    }

    public function test_a_wrong_private_key_throws_a_security_fault(): void
    {
        [, $certificate] = $this->keyAndCertificate();
        [$otherKey] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));

        $this->expectException(SecurityFault::class);
        (new Decrypt($otherKey))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_a_tampered_ciphertext_throws_a_security_fault(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));

        $cipherValue = $this->body($document)->getElementsByTagNameNS(self::XENC, 'CipherValue')->item(0);
        static::assertInstanceOf(Element::class, $cipherValue);
        $cipherValue->textContent = base64_encode('garbage that will not decrypt to anything valid');

        $this->expectException(SecurityFault::class);
        (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_a_missing_encrypted_key_throws_a_security_fault(): void
    {
        [$key] = $this->keyAndCertificate();
        $document = $this->envelope();

        $this->expectException(SecurityFault::class);
        (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_all_failure_causes_produce_one_identical_security_fault(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        [$otherKey] = $this->keyAndCertificate();

        $causes = [
            'wrong-key' => function () use ($certificate, $otherKey): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));
                (new Decrypt($otherKey))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            'tampered' => function () use ($certificate, $key): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));
                $cipherValue = $this->body($document)->getElementsByTagNameNS(self::XENC, 'CipherValue')->item(0);
                static::assertInstanceOf(Element::class, $cipherValue);
                $cipherValue->textContent = base64_encode('garbage that will not decrypt');
                (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            'no-encrypted-key' => function () use ($key): void {
                $document = $this->envelope();
                (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            // The allow-list and structural refusals. These are here for uniformity coverage, not to pin the
            // gates: whether a gate still fires is settled at the engine layer, where the reason is visible and
            // a correctly encrypted body proves the refusal was the policy rather than a failed decrypt (see
            // EncryptedDataRoundTripTest's rejected/widened pair). At this boundary every cause shares one
            // message by design, so what these rows prove is that these causes are indistinguishable from the
            // others, which is the property this test exists for.
            'disallowed-data-encryption-method' => function () use ($certificate, $key): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));
                $method = $this->body($document)->getElementsByTagNameNS(self::XENC, 'EncryptionMethod')->item(0);
                static::assertInstanceOf(Element::class, $method);
                $method->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc');
                (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            'unknown-data-encryption-method' => function () use ($certificate, $key): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));
                $method = $this->body($document)->getElementsByTagNameNS(self::XENC, 'EncryptionMethod')->item(0);
                static::assertInstanceOf(Element::class, $method);
                $method->setAttribute('Algorithm', 'urn:not-a-cipher');
                (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            'disallowed-key-encryption-method' => function () use ($certificate, $key): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));
                $method = $this->security($document)->getElementsByTagNameNS(self::XENC, 'EncryptionMethod')->item(0);
                static::assertInstanceOf(Element::class, $method);
                $method->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#rsa-1_5');
                (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            'encrypted-key-outside-our-container' => function () use ($certificate, $key): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest($this->security($document), $certificate));
                $encryptedKey = $this->security($document)->getElementsByTagNameNS(self::XENC, 'EncryptedKey')->item(0);
                static::assertInstanceOf(Element::class, $encryptedKey);
                // Moved into the Body: still in the document, no longer addressed to this receiver.
                $this->body($document)->appendChild($encryptedKey);
                (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
        ];

        $messages = [];
        $types = [];
        foreach ($causes as $name => $cause) {
            try {
                $cause();
                static::fail('Expected a failure for cause: '.$name);
            } catch (SecurityFault $fault) {
                $messages[$name] = $fault->getMessage();
                $types[$name] = $fault::class;
            }
        }

        // Derived from the table rather than hardcoded, so adding a cause cannot leave it silently unchecked.
        static::assertCount(count($causes), $messages);
        static::assertCount(1, array_unique($messages), 'Every failure cause must expose one identical message.');
        static::assertCount(1, array_unique($types), 'Every failure cause must surface the same exception type.');
    }

    private function encryptor(): Encryptor
    {
        return new Encryptor(
            new TargetLocator(),
            new SessionKeyFactory(),
            new Cipher(),
            new EncryptedDataBuilder((new WsuIdConvention())->minter()),
            new KeyTransport(),
            new EncryptedKeyBuilder(),
            new ExternalPartSealer(
                new Cipher(),
                new ExternalEncryptedDataBuilder((new WsuIdConvention())->minter()),
            ),
        );
    }


    private function encryptionRequest(Element $container, Certificate $certificate): EncryptionRequest
    {
        return new EncryptionRequest(
            container: $container,
            targets: [new EncryptionTarget(Target::element(self::SOAP, 'Body'), EncryptionMode::Content)],
            recipientCertificate: $certificate,
            keyIdentifier: new DirectReferenceKeyIdentifier('RecipientToken', self::X509_TOKEN),
            dataEncryptionMethod: DataEncryptionMethod::AES256_GCM,
            keyTransportAlgorithm: KeyTransportAlgorithm::legacyMgf1p(),
        );
    }

    private function envelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header><wsse:Security/></soap:Header>'
            .'<soap:Body><app:Op xmlns:app="urn:app"><app:n>5</app:n>text</app:Op></soap:Body>'
            .'</soap:Envelope>',
        );
    }

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }

    private function security(Document $document): Element
    {
        $security = SecurityHeader::locate($document, SoapVersion::fromDocument($document));
        static::assertInstanceOf(Element::class, $security);

        return $security;
    }

    /**
     * @return list<Element>
     */
    private function encryptedData(Document $document): array
    {
        $nodes = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, 'EncryptedData') as $node) {
            if ($node instanceof Element) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }

    /**
     * Moves the wsu:Id minted on the EncryptedData onto a native, namespace-less @Id, keeping the same value
     * so the DataReference URI="#..." still points at it. This reproduces a common interop wire shape
     * where the encrypted part carries the native XML-Encryption id rather than the wsu:Id.
     */
    private function relabelToNativeId(Document $document): void
    {
        $encryptedData = $this->encryptedData($document)[0] ?? null;
        static::assertInstanceOf(Element::class, $encryptedData);

        $id = $encryptedData->getAttributeNS(self::WSU, 'Id');
        static::assertNotSame('', $id);

        $encryptedData->removeAttributeNS(self::WSU, 'Id');
        $encryptedData->setAttribute('Id', $id);
    }

    private function innerXml(Element $element): string
    {
        $inner = '';
        foreach ($element->childNodes as $child) {
            $inner .= $element->ownerDocument->saveXML($child);
        }

        return $inner;
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

        $csr = openssl_csr_new(['commonName' => 'wsse-recipient-test'], $private);
        static::assertNotFalse($csr);

        $certificate = openssl_csr_sign($csr, null, $private, 365);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return [new Key($privatePem), new Certificate($certificatePem)];
    }
}
