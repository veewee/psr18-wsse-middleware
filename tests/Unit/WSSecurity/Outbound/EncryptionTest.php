<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes\DataProvider;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\DirectReferenceKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\Strategy\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\Decryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptedKeyReader;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\PartLocator;
use VeeWee\Xml\Dom\Document;

/**
 * Covers the Encryption block: configuration resolution against a recording encryptor, the inline vs
 * BST key-reference dispatch, and the real-crypto functional path proven by the engine's own
 * Decryptor round-trip.
 */
final class EncryptionTest extends OutboundTestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';

    public function test_it_uses_profile_algorithms_by_default(): void
    {
        $encryptor = new RecordingEncryptor();
        (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)($this->context($this->plainEnvelope()));

        $request = $encryptor->lastRequest();
        static::assertSame(DataEncryptionMethod::AES256_GCM, $request->dataEncryptionMethod);
        static::assertSame(KeyEncryptionMethod::RSA_OAEP, $request->keyTransportAlgorithm->method);
        static::assertSame(OaepHash::Sha1, $request->keyTransportAlgorithm->oaepHash);
    }

    public function test_a_per_block_data_encryption_override_wins(): void
    {
        $encryptor = new RecordingEncryptor();
        $block = (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_CBC);
        $block($this->context($this->plainEnvelope()));

        static::assertSame(DataEncryptionMethod::AES128_CBC, $encryptor->lastRequest()->dataEncryptionMethod);
    }

    public function test_a_per_block_key_encryption_override_wins(): void
    {
        $encryptor = new RecordingEncryptor();
        $block = (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)
            ->withKeyEncryptionMethod(KeyEncryptionMethod::RSA_OAEP_MGF1P);
        $block($this->context($this->plainEnvelope()));

        static::assertSame(KeyEncryptionMethod::RSA_OAEP_MGF1P, $encryptor->lastRequest()->keyTransportAlgorithm->method);
    }

    public function test_an_atomic_key_transport_override_wins(): void
    {
        $encryptor = new RecordingEncryptor();
        $block = (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)
            ->withKeyTransportAlgorithm(KeyTransportAlgorithm::oaepSha256());
        $block($this->context($this->plainEnvelope()));

        $algorithm = $encryptor->lastRequest()->keyTransportAlgorithm;
        static::assertSame(KeyEncryptionMethod::RSA_OAEP, $algorithm->method);
        static::assertSame(OaepHash::Sha256, $algorithm->oaepHash);
    }

    public function test_an_rsa_1_5_transport_carries_a_null_oaep_hash(): void
    {
        $encryptor = new RecordingEncryptor();
        $block = (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)
            ->withKeyTransportAlgorithm(KeyTransportAlgorithm::rsa1_5());
        $block($this->context($this->plainEnvelope()));

        $algorithm = $encryptor->lastRequest()->keyTransportAlgorithm;
        static::assertSame(KeyEncryptionMethod::RSA_1_5, $algorithm->method);
        static::assertNull($algorithm->oaepHash);
    }

    public function test_a_context_profile_drives_the_outbound_oaep_hash(): void
    {
        $encryptor = new RecordingEncryptor();
        $profile = new SecurityProfile(oaepHash: OaepHash::Sha256);
        (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)($this->context($this->plainEnvelope(), $profile));

        static::assertSame(OaepHash::Sha256, $encryptor->lastRequest()->keyTransportAlgorithm->oaepHash);
    }

    public function test_it_encrypts_with_oaep_sha256_and_round_trips_through_the_engine_decryptor(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelopeWithSecurity();
        $originalBody = $document->stringifyNode($this->only($document, self::SOAP12, 'Body'));

        $block = (new Encryption($certificate))->withEncryptor($this->realEncryptor())->withKeyTransportAlgorithm(KeyTransportAlgorithm::oaepSha256());
        $block($this->context($document));

        // The xenc:EncryptionMethod carries explicit SHA-256 digest and MGF children.
        $encryptedKey = $this->only($document, self::XENC, 'EncryptedKey');
        $method = $encryptedKey->getElementsByTagNameNS(self::XENC, 'EncryptionMethod')->item(0);
        static::assertInstanceOf(Element::class, $method);
        static::assertSame(1, $method->getElementsByTagNameNS('http://www.w3.org/2009/xmlenc11#', 'MGF')->count());

        (new Decryptor(new EncryptedKeyReader(new KeyTransport()), new EncryptedDataReader(new Cipher())))
            ->decrypt($document, new DecryptionRequest($key));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedData'));
        static::assertSame($originalBody, $document->stringifyNode($this->only($document, self::SOAP12, 'Body')));
    }

    public function test_a_context_profile_overrides_the_default(): void
    {
        $encryptor = new RecordingEncryptor();
        $profile = new SecurityProfile(dataEncryptionMethod: DataEncryptionMethod::AES256_CBC);
        (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)($this->context($this->plainEnvelope(), $profile));

        static::assertSame(DataEncryptionMethod::AES256_CBC, $encryptor->lastRequest()->dataEncryptionMethod);
    }

    public function test_with_methods_are_immutable(): void
    {
        $original = (new Encryption($this->recipientCertificate()))->withEncryptor(new RecordingEncryptor());

        static::assertNotSame($original, $original->withParts([Part::timestamp()]));
        static::assertNotSame($original, $original->withDataEncryptionMethod(DataEncryptionMethod::AES128_CBC));
        static::assertNotSame($original, $original->withKeyEncryptionMethod(KeyEncryptionMethod::RSA_OAEP_MGF1P));
        static::assertNotSame($original, $original->withKeyTransportAlgorithm(KeyTransportAlgorithm::oaepSha256()));
    }

    public function test_with_encryptor_routes_encryption_to_the_given_encryptor(): void
    {
        $encryptor = new RecordingEncryptor();
        (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)($this->context($this->plainEnvelope()));

        // lastRequest() throws unless encrypt() ran on the injected double, proving the override is used.
        static::assertInstanceOf(DataEncryptionMethod::class, $encryptor->lastRequest()->dataEncryptionMethod);
    }

    public function test_the_default_part_is_the_body_only(): void
    {
        $encryptor = new RecordingEncryptor();
        (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)($this->context($this->plainEnvelope()));

        $parts = $encryptor->lastRequest()->parts;
        static::assertCount(1, $parts);
        static::assertTrue($parts[0]->equals(Part::body()));
    }

    public function test_explicit_parts_override_the_default(): void
    {
        $encryptor = new RecordingEncryptor();
        $block = (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)
            ->withParts([Part::body(), Part::timestamp()]);
        $block($this->context($this->plainEnvelope()));

        $parts = $encryptor->lastRequest()->parts;
        static::assertCount(2, $parts);
        static::assertTrue($parts[0]->equals(Part::body()));
        static::assertTrue($parts[1]->equals(Part::timestamp()));
    }

    public function test_the_default_key_reference_does_not_use_deprecated_rsa_padding(): void
    {
        $encryptor = new RecordingEncryptor();
        (new Encryption($this->recipientCertificate()))->withEncryptor($encryptor)($this->context($this->plainEnvelope()));

        static::assertNotSame(KeyEncryptionMethod::RSA_1_5, $encryptor->lastRequest()->keyTransportAlgorithm->method);
    }

    /**
     * @return iterable<string, array{0: EncKeyRef, 1: class-string}>
     */
    public static function inlineKeyReferences(): iterable
    {
        yield 'subject-key-identifier' => [EncKeyRef::SubjectKeyIdentifier, X509SubjectKeyIdentifier::class];
        yield 'issuer-serial' => [EncKeyRef::IssuerSerial, IssuerSerialKeyIdentifier::class];
        yield 'thumbprint' => [EncKeyRef::Thumbprint, ThumbprintKeyIdentifier::class];
    }

    /**
     * @param class-string $expectedStrategy
     */
    #[DataProvider('inlineKeyReferences')]
    public function test_inline_key_references_embed_no_bst(EncKeyRef $encKeyRef, string $expectedStrategy): void
    {
        $encryptor = new RecordingEncryptor();
        $document = $this->plainEnvelope();
        (new Encryption($this->recipientCertificate(), encKeyRef: $encKeyRef))->withEncryptor($encryptor)($this->context($document));

        static::assertCount(0, $this->elements($document, self::WSSE, 'BinarySecurityToken'));
        static::assertInstanceOf($expectedStrategy, $encryptor->lastRequest()->keyIdentifier);
    }

    public function test_binary_security_token_embeds_a_token_and_wires_a_direct_reference(): void
    {
        $encryptor = new RecordingEncryptor();
        $document = $this->plainEnvelope();
        (new Encryption($this->recipientCertificate(), encKeyRef: EncKeyRef::BinarySecurityToken))->withEncryptor($encryptor)($this->context($document));

        $bst = $this->only($document, self::WSSE, 'BinarySecurityToken');
        $tokenId = $bst->getAttributeNS(self::WSU, 'Id');

        $keyIdentifier = $encryptor->lastRequest()->keyIdentifier;
        static::assertInstanceOf(DirectReferenceKeyIdentifier::class, $keyIdentifier);

        $keyInfo = $keyIdentifier->apply($document, $this->recipientCertificate());
        static::assertStringContainsString('#'.$tokenId, $document->stringifyNode($keyInfo));
    }

    public function test_it_encrypts_the_body_and_round_trips_through_the_engine_decryptor(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelopeWithSecurity();
        $originalBody = $document->stringifyNode($this->only($document, self::SOAP12, 'Body'));

        (new Encryption($certificate))->withEncryptor($this->realEncryptor())($this->context($document));

        // One EncryptedKey in the Security header, one EncryptedData replacing the Body content, one DataReference.
        $encryptedKey = $this->only($document, self::XENC, 'EncryptedKey');
        static::assertSame('Security', $encryptedKey->parentNode?->localName);
        static::assertCount(1, $this->elements($document, self::XENC, 'EncryptedData'));
        static::assertSame(1, $encryptedKey->getElementsByTagNameNS(self::XENC, 'DataReference')->count());

        $encryptedData = $this->only($document, self::XENC, 'EncryptedData');
        static::assertSame('http://www.w3.org/2001/04/xmlenc#Content', $encryptedData->getAttribute('Type'));

        (new Decryptor(new EncryptedKeyReader(new KeyTransport()), new EncryptedDataReader(new Cipher())))
            ->decrypt($document, new DecryptionRequest($key));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedData'));
        static::assertSame($originalBody, $document->stringifyNode($this->only($document, self::SOAP12, 'Body')));
    }

    public function test_an_overridden_data_algorithm_reaches_the_encrypted_message(): void
    {
        [$key, $certificate] = $this->keyAndCertificate();
        $document = $this->envelopeWithSecurity();

        $block = (new Encryption($certificate))->withEncryptor($this->realEncryptor())
            ->withDataEncryptionMethod(DataEncryptionMethod::AES256_CBC);
        $block($this->context($document));

        $encryptedData = $this->only($document, self::XENC, 'EncryptedData');
        $method = $encryptedData->getElementsByTagNameNS(self::XENC, 'EncryptionMethod')->item(0);
        static::assertInstanceOf(Element::class, $method);
        static::assertSame(DataEncryptionMethod::AES256_CBC->value, $method->getAttribute('Algorithm'));

        (new Decryptor(new EncryptedKeyReader(new KeyTransport()), new EncryptedDataReader(new Cipher())))
            ->decrypt($document, new DecryptionRequest($key));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedData'));
    }

    private function realEncryptor(): Encryptor
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

    private function plainEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'"><soap:Header/><soap:Body><data>x</data></soap:Body></soap:Envelope>'
        );
    }

    private function envelopeWithSecurity(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'" xmlns:wsse="'.self::WSSE.'">'
            .'<soap:Header><wsse:Security/></soap:Header>'
            .'<soap:Body><app:Op xmlns:app="urn:app"><app:n>5</app:n>text</app:Op></soap:Body>'
            .'</soap:Envelope>'
        );
    }

    private function recipientCertificate(): Certificate
    {
        return $this->keyAndCertificate()[1];
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

        // Self-sign with v3 extensions so the SubjectKeyIdentifier reference path has a value to read.
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

        return [new Key($privatePem), new Certificate($certificatePem)];
    }
}
