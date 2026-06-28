<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\PartLocator;
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

        $this->encryptor()->encrypt($document, $this->encryptionRequest($certificate));
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

        $this->encryptor()->encrypt($document, $this->encryptionRequest($certificate));

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
        $this->encryptor()->encrypt($document, $this->encryptionRequest($certificate));

        $this->expectException(SecurityFault::class);
        (new Decrypt($otherKey))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
    }

    public function test_a_tampered_ciphertext_throws_a_security_fault(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest($certificate));

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
                $this->encryptor()->encrypt($document, $this->encryptionRequest($certificate));
                (new Decrypt($otherKey))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            'tampered' => function () use ($certificate, $key): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest($certificate));
                $cipherValue = $this->body($document)->getElementsByTagNameNS(self::XENC, 'CipherValue')->item(0);
                static::assertInstanceOf(Element::class, $cipherValue);
                $cipherValue->textContent = base64_encode('garbage that will not decrypt');
                (new Decrypt($key))(new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()));
            },
            'no-encrypted-key' => function () use ($key): void {
                $document = $this->envelope();
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

        static::assertCount(3, $messages);
        static::assertCount(1, array_unique($messages), 'Every failure cause must expose one identical message.');
        static::assertCount(1, array_unique($types), 'Every failure cause must surface the same exception type.');
    }

    private function encryptor(): Encryptor
    {
        return new Encryptor(
            new PartLocator(),
            new SessionKeyFactory(),
            new Cipher(),
            new EncryptedDataBuilder(new WsuIdMinter()),
            new KeyTransport(),
            new EncryptedKeyBuilder(),
        );
    }


    private function encryptionRequest(Certificate $certificate): EncryptionRequest
    {
        return new EncryptionRequest(
            parts: [Part::body()],
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
