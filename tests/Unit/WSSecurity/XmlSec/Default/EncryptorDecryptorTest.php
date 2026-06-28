<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec\Default;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\Decryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\PartLocator;
use VeeWee\Xml\Dom\Document;

/**
 * The strong proof of the encrypt/decrypt round-trip through the real OpenSSL\ path, plus the security arms:
 * a uniform inbound failure for every cause (wrong key, tampered ciphertext, non-SHA-1 OAEP, over-cap), the
 * part-count cap before any crypto, and the missing-header outbound guard.
 */
final class EncryptorDecryptorTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const X509_TOKEN = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3';

    /**
     * @return iterable<string, array{0: DataEncryptionMethod}>
     */
    public static function dataMethods(): iterable
    {
        yield 'aes-256-gcm' => [DataEncryptionMethod::AES256_GCM];
        yield 'aes-128-cbc' => [DataEncryptionMethod::AES128_CBC];
    }

    #[DataProvider('dataMethods')]
    public function test_it_round_trips_the_body(DataEncryptionMethod $method): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $originalBody = $this->innerXml($this->body($document));

        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, $method));

        // The Body now carries an xenc:EncryptedData and the header an xenc:EncryptedKey.
        static::assertCount(1, $this->encryptedData($document));
        static::assertNotNull($this->encryptedKey($document));

        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));

        static::assertSame($originalBody, $this->innerXml($this->body($document)));
        static::assertCount(0, $this->encryptedData($document));
    }

    public function test_it_round_trips_a_header_element_in_element_mode(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope(withCustom: true);

        $this->encryptor()->encrypt(
            $document,
            $this->encryptionRequest([Part::element('urn:app', 'Custom')], $certificate, DataEncryptionMethod::AES256_GCM),
        );

        $encryptedData = $this->encryptedData($document);
        static::assertCount(1, $encryptedData);
        static::assertSame('http://www.w3.org/2001/04/xmlenc#Element', $encryptedData[0]->getAttribute('Type'));

        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));

        static::assertStringContainsString('<app:Custom', $document->toXmlString());
        static::assertStringContainsString('payload', $document->toXmlString());
    }

    public function test_it_round_trips_multiple_parts_with_one_shared_key(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope(withTimestamp: true);

        $this->encryptor()->encrypt(
            $document,
            $this->encryptionRequest([Part::body(), Part::timestamp()], $certificate, DataEncryptionMethod::AES256_GCM),
        );

        // One EncryptedKey, two DataReferences, two EncryptedData.
        static::assertCount(2, $this->encryptedData($document));
        $references = $this->encryptedKey($document)->getElementsByTagNameNS(self::XENC, 'DataReference');
        static::assertSame(2, $references->count());

        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));

        static::assertCount(0, $this->encryptedData($document));
    }

    public function test_the_encrypted_key_is_placed_before_a_pre_existing_signature(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope(withStaleSignature: true);

        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));

        $order = [];
        foreach ($this->security($document)->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        static::assertSame(['EncryptedKey', 'Signature'], $order);
    }

    public function test_it_throws_when_no_security_header_exists(): void
    {
        [, $certificate] = $this->keyAndCertificate();
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Header/><soap:Body><data>x</data></soap:Body></soap:Envelope>',
        );

        $this->expectException(EncryptionFailed::class);
        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));
    }

    public function test_a_wrong_private_key_fails_uniformly(): void
    {
        [, $certificate] = $this->keyAndCertificate();
        [$otherKey] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));

        $this->expectException(DecryptionFailed::class);
        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($otherKey)));
    }

    public function test_a_tampered_ciphertext_fails_uniformly(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));

        $cipherValue = $this->body($document)->getElementsByTagNameNS(self::XENC, 'CipherValue')->item(0);
        static::assertInstanceOf(Element::class, $cipherValue);
        $cipherValue->textContent = base64_encode('garbage that will not decrypt to anything valid at all');

        $this->expectException(DecryptionFailed::class);
        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));
    }

    public function test_a_non_sha1_oaep_digest_is_refused(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));

        // Inject a SHA-256 DigestMethod into the EncryptedKey's EncryptionMethod.
        $encryptionMethod = $this->encryptedKey($document)->getElementsByTagNameNS(self::XENC, 'EncryptionMethod')->item(0);
        static::assertInstanceOf(Element::class, $encryptionMethod);
        $digestMethod = $document->toUnsafeDocument()->createElementNS(self::DS, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $encryptionMethod->appendChild($digestMethod);

        $this->expectException(DecryptionFailed::class);
        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));
    }

    public function test_a_non_sha1_oaep_mgf_is_refused(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));

        // A non-SHA-1 MGF in the canonical xenc11 namespace must be refused.
        $encryptionMethod = $this->encryptedKey($document)->getElementsByTagNameNS(self::XENC, 'EncryptionMethod')->item(0);
        static::assertInstanceOf(Element::class, $encryptionMethod);
        $mgf = $document->toUnsafeDocument()->createElementNS('http://www.w3.org/2009/xmlenc11#', 'xenc11:MGF');
        $mgf->setAttribute('Algorithm', 'http://www.w3.org/2009/xmlenc11#mgf1sha256');
        $encryptionMethod->appendChild($mgf);

        $this->expectException(DecryptionFailed::class);
        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));
    }

    public function test_an_absent_oaep_digest_is_accepted(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));

        // No DigestMethod child: SHA-1 default applies and the round-trip succeeds.
        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));

        static::assertCount(0, $this->encryptedData($document));
    }

    public function test_over_cap_data_references_are_rejected_before_any_crypto(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelope();
        $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));

        // Inflate the ReferenceList past the cap. Also corrupt the wrapped key so that, were the cap not
        // enforced first, the unwrap would fail too: the test proves the cap rejects before that work runs.
        $referenceList = $this->encryptedKey($document)->getElementsByTagNameNS(self::XENC, 'ReferenceList')->item(0);
        static::assertInstanceOf(Element::class, $referenceList);
        for ($i = 0; $i <= Decryptor::MAX_ENCRYPTED_PARTS; $i++) {
            $reference = $document->toUnsafeDocument()->createElementNS(self::XENC, 'xenc:DataReference');
            $reference->setAttribute('URI', '#bogus-'.$i);
            $referenceList->appendChild($reference);
        }

        $this->expectException(DecryptionFailed::class);
        $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));
    }

    public function test_all_decrypt_failures_share_one_exception_type(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        [$otherKey] = $this->keyAndCertificate();

        $causes = [
            'wrong-key' => function () use ($certificate, $otherKey): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));
                $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($otherKey)));
            },
            'tampered' => function () use ($certificate, $key): void {
                $document = $this->envelope();
                $this->encryptor()->encrypt($document, $this->encryptionRequest([Part::body()], $certificate, DataEncryptionMethod::AES256_GCM));
                $cipherValue = $this->body($document)->getElementsByTagNameNS(self::XENC, 'CipherValue')->item(0);
                static::assertInstanceOf(Element::class, $cipherValue);
                $cipherValue->textContent = base64_encode('garbage that will not decrypt');
                $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));
            },
            'no-encrypted-key' => function () use ($key): void {
                $document = $this->envelope();
                $this->decryptor()->decrypt($document, new DecryptionRequest(KeyHandle::for($key)));
            },
        ];

        $messages = [];
        foreach ($causes as $name => $cause) {
            try {
                $cause();
                static::fail('Expected a failure for cause: '.$name);
            } catch (DecryptionFailed $exception) {
                $messages[$name] = $exception->getMessage();
            }
        }

        // A distinguishing message is itself an oracle, so every cause must share one identical message.
        static::assertCount(3, $messages);
        static::assertCount(1, array_unique($messages), 'All decryption failures must expose one identical message.');
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

    private function decryptor(): Decryptor
    {
        return new Decryptor(
            new EncryptedKeyReader(new KeyTransport()),
            new EncryptedDataReader(new Cipher()),
        );
    }

    /**
     * @param non-empty-list<Part> $parts
     */
    private function encryptionRequest(array $parts, Certificate $certificate, DataEncryptionMethod $method): EncryptionRequest
    {
        return new EncryptionRequest(
            parts: $parts,
            recipientCertificate: KeyHandle::for($certificate),
            keyIdentifier: new DirectReferenceKeyIdentifier('RecipientToken', self::X509_TOKEN),
            dataEncryptionMethod: $method,
            keyTransportAlgorithm: KeyTransportAlgorithm::legacyMgf1p(),
        );
    }

    private function envelope(bool $withTimestamp = false, bool $withCustom = false, bool $withStaleSignature = false): Document
    {
        $timestamp = $withTimestamp ? '<wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><wsu:Created>2026-01-01T00:00:00Z</wsu:Created></wsu:Timestamp>' : '';
        $stale = $withStaleSignature ? '<ds:Signature xmlns:ds="'.self::DS.'"><ds:SignatureValue>stale</ds:SignatureValue></ds:Signature>' : '';
        $custom = $withCustom ? '<app:Custom xmlns:app="urn:app">payload<app:inner>deep</app:inner></app:Custom>' : '';

        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header><wsse:Security>'.$timestamp.$stale.'</wsse:Security>'.$custom.'</soap:Header>'
            .'<soap:Body><app:Op xmlns:app="urn:app"><app:n>5</app:n>text</app:Op></soap:Body>'
            .'</soap:Envelope>',
        );
    }

    private function security(Document $document): Element
    {
        $security = $document->toUnsafeDocument()->getElementsByTagNameNS(self::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $security);

        return $security;
    }

    private function encryptedKey(Document $document): Element
    {
        $encryptedKey = $document->toUnsafeDocument()->getElementsByTagNameNS(self::XENC, 'EncryptedKey')->item(0);
        static::assertInstanceOf(Element::class, $encryptedKey);

        return $encryptedKey;
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

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
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
