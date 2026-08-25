<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\RequiresPhp;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Decryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalEncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\ExternalEncryptedDataReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\DigestCalculator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\ReferenceCollector;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SignedInfoBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\Signer;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use VeeWee\Xml\Dom\Document;

/**
 * Proves the combined outbound path: signing (D2) followed by encryption (D3) leaves the engine's
 * canonical Security-header order (xenc:EncryptedKey before ds:Signature) and the body still decrypts.
 * Real signing exercises C14N, so this carries the PHP floor and runs in the Docker matrix.
 */
#[RequiresPhp('>= 8.4.21')]
final class SignThenEncryptOrderTest extends OutboundTestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_encrypted_key_precedes_the_signature_after_sign_then_encrypt(): void
    {
        $clientCertificate = $this->clientCertificate();
        [$recipientKey, $recipientCertificate] = $this->recipientKeyAndCertificate();
        $document = $this->signableEnvelope();
        $context = $this->context($document);

        (new Signature($clientCertificate, keyRef: KeyRef::BinarySecurityToken))->withSigner($this->realSigner())($context);
        (new Encryption($recipientCertificate))->withEncryptor($this->realEncryptor())($context);

        $order = [];
        foreach ($this->only($document, self::WSSE, 'Security')->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        static::assertContains('EncryptedKey', $order);
        static::assertContains('Signature', $order);
        static::assertLessThan(
            array_search('Signature', $order, true),
            array_search('EncryptedKey', $order, true),
            'xenc:EncryptedKey must precede ds:Signature in the Security header.',
        );

        // The encrypted body still round-trips after the combined operation.
        (new Decryptor(new EncryptedKeyReader(new KeyTransport()), new EncryptedDataReader(new Cipher()), new EncryptedDataLocator((new WsuIdConvention())->lookup()), new ExternalEncryptedDataReader(new Cipher())))
            ->decrypt($document, new DecryptionRequest($this->security($document), $recipientKey));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedData'));
        static::assertStringContainsString('<data>x</data>', $document->toXmlString());
    }

    public function test_the_signature_survives_the_encryption_pass(): void
    {
        // The ds:SignatureValue survives the encryption pass unchanged (the signature is not re-encrypted).
        $clientCertificate = $this->clientCertificate();
        [, $recipientCertificate] = $this->recipientKeyAndCertificate();
        $document = $this->signableEnvelope();
        $context = $this->context($document);

        (new Signature($clientCertificate, keyRef: KeyRef::BinarySecurityToken))->withSigner($this->realSigner())($context);
        (new Encryption($recipientCertificate))->withEncryptor($this->realEncryptor())($context);

        static::assertCount(1, $this->elements($document, self::DS, 'SignatureValue'));
    }

    public function test_signing_and_encrypting_with_one_certificate_share_a_single_token(): void
    {
        // When the signature and the encryption both reference the same certificate by direct reference, the
        // token is embedded once and reused, not duplicated.
        $clientCertificate = $this->clientCertificate();
        $document = $this->signableEnvelope();
        $context = $this->context($document);

        (new Signature($clientCertificate, keyRef: KeyRef::BinarySecurityToken))->withSigner($this->realSigner())($context);
        (new Encryption($clientCertificate->publicCertificate(), encKeyRef: EncKeyRef::BinarySecurityToken))->withEncryptor($this->realEncryptor())($context);

        static::assertCount(1, $this->elements($document, self::WSSE, 'BinarySecurityToken'));
    }

    /**
     * The Security header the encrypting block wrote into, which is also the container the wrapped key is read
     * back out of.
     */
    private function security(Document $document): Element
    {
        $security = SecurityHeader::locate($document, SoapVersion::fromDocument($document));
        static::assertInstanceOf(Element::class, $security);

        return $security;
    }

    private function realSigner(): Signer
    {
        $canonicalizer = new DomCanonicalizer();

        return new Signer(
            new ReferenceCollector((new WsuIdConvention())->minter(), new TargetLocator((new WsuIdConvention())->lookup())),
            new DigestCalculator($canonicalizer, new Digest()),
            new SignedInfoBuilder(),
            $canonicalizer,
            new OpenSslSigner(),
            (new WsuIdConvention())->lookup(),
        );
    }

    private function realEncryptor(): Encryptor
    {
        return new Encryptor(
            new TargetLocator(),
            new SessionKeyFactory(),
            new Cipher(),
            new EncryptedDataBuilder((new WsuIdConvention())->minter()),
            new KeyTransport(),
            new EncryptedKeyBuilder(),
            new ExternalEncryptedDataBuilder((new WsuIdConvention())->minter()),
        );
    }

    private function signableEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope'
            .' xmlns:soap="'.self::SOAP12.'"'
            .' xmlns:wsu="'.self::WSU.'">'
            .'<soap:Header>'
            .'<wsu:Timestamp><wsu:Created>2026-01-01T00:00:00Z</wsu:Created></wsu:Timestamp>'
            .'</soap:Header>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function clientCertificate(): ClientCertificate
    {
        [$privatePem, $certificatePem] = $this->keyPair('wsse-signature-test');

        return new ClientCertificate($certificatePem.$privatePem);
    }

    /**
     * @return array{0: Key, 1: Certificate}
     */
    private function recipientKeyAndCertificate(): array
    {
        [$privatePem, $certificatePem] = $this->keyPair('wsse-recipient-test');

        return [new Key($privatePem), new Certificate($certificatePem)];
    }

    /**
     * @return array{0: string, 1: string} the private and certificate PEM
     */
    private function keyPair(string $commonName): array
    {
        $private = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        static::assertInstanceOf(OpenSSLAsymmetricKey::class, $private);

        static::assertTrue(openssl_pkey_export($private, $privatePem));
        static::assertIsString($privatePem);

        $csr = openssl_csr_new(['commonName' => $commonName], $private);
        static::assertNotFalse($csr);

        $config = tempnam(sys_get_temp_dir(), 'wsse-x509-');
        static::assertIsString($config);
        file_put_contents($config, "[v3]\nsubjectKeyIdentifier = hash\n");

        $certificate = openssl_csr_sign($csr, null, $private, 365, [
            'config' => $config,
            'x509_extensions' => 'v3',
        ]);
        unlink($config);
        static::assertNotFalse($certificate);

        static::assertTrue(openssl_x509_export($certificate, $certificatePem));
        static::assertIsString($certificatePem);

        return [$privatePem, $certificatePem];
    }
}
