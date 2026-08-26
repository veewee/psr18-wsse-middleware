<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\RequiresPhp;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\AsymmetricSigningKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\GeneratedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\SymmetricSigningKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * The outbound SymmetricBinding shape: one xenc:EncryptedKey shared by an HMAC signature and an encryption,
 * expressed by handing both blocks the same key source.
 */
#[RequiresPhp('>= 8.4.21')]
final class SymmetricBindingTest extends OutboundTestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const WSSE11 = 'http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd';
    private const ENCRYPTED_KEY_SHA1
        = 'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKeySHA1';

    public function test_a_signature_and_an_encryption_sharing_a_source_write_one_encrypted_key(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signableEnvelope();
        $context = $this->symmetricContext($document);
        $key = new GeneratedSessionKey($fixture->leafCertificate, EncKeyRef::Thumbprint);

        (new Signature(new SymmetricSigningKey($key)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption($key))->withParts([Part::body()])($context);

        static::assertCount(1, $this->elements($document, self::XENC, 'EncryptedKey'));
        static::assertCount(1, $this->elements($document, self::XENC, 'ReferenceList'));
        static::assertCount(1, $this->elements($document, self::XENC, 'EncryptedData'));
    }

    /**
     * The header order a receiver processes top-down: the key it needs, then the list of what the key opens,
     * then the signature that references both.
     */
    public function test_the_reference_list_stands_beside_the_key_and_before_the_signature(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signableEnvelope();
        $context = $this->symmetricContext($document);
        $key = new GeneratedSessionKey($fixture->leafCertificate);

        (new Signature(new SymmetricSigningKey($key)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption($key))->withParts([Part::body()])($context);

        $security = $fixture->security($document);
        $order = [];
        foreach ($security->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        static::assertSame(['EncryptedKey', 'ReferenceList', 'Signature'], $order);
    }

    public function test_the_signature_names_the_key_by_its_encrypted_key_sha1(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signableEnvelope();
        $key = new GeneratedSessionKey($fixture->leafCertificate);

        (new Signature(new SymmetricSigningKey($key)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->symmetricContext($document));

        $keyIdentifier = $this->only($document, self::DS, 'Signature')
            ->getElementsByTagNameNS(self::WSSE, 'KeyIdentifier')
            ->item(0);
        static::assertInstanceOf(Element::class, $keyIdentifier);
        static::assertSame(self::ENCRYPTED_KEY_SHA1, $keyIdentifier->getAttribute('ValueType'));

        // base64(SHA-1(...)) of the wrapped bytes: twenty bytes, whatever the key length.
        $decoded = base64_decode($keyIdentifier->textContent, true);
        static::assertIsString($decoded);
        static::assertSame(20, strlen($decoded));
    }

    /**
     * A receiver enforcing the Basic Security Profile classifies a reference by the type it declares and
     * refuses one it cannot classify, reporting whatever shape it guessed at rather than what was wrong. So the
     * session-key reference says what it points at.
     */
    public function test_the_key_reference_declares_the_token_type_it_points_at(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signableEnvelope();

        (new Signature(new SymmetricSigningKey(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->symmetricContext($document));

        $reference = $this->only($document, self::DS, 'Signature')
            ->getElementsByTagNameNS(self::WSSE, 'SecurityTokenReference')
            ->item(0);
        static::assertInstanceOf(Element::class, $reference);
        static::assertSame(
            'http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#EncryptedKey',
            $reference->getAttributeNS(self::WSSE11, 'TokenType'),
        );
    }

    public function test_a_symmetric_signature_needs_no_encryption_to_carry_its_key(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signableEnvelope();

        (new Signature(new SymmetricSigningKey(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->symmetricContext($document));

        // The key is written purely to convey the secret, so it carries no list of parts it opens.
        static::assertCount(1, $this->elements($document, self::XENC, 'EncryptedKey'));
        static::assertCount(0, $this->elements($document, self::XENC, 'ReferenceList'));
    }

    public function test_the_signature_method_decides_the_length_the_key_is_minted_at(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signableEnvelope();

        // HMAC-SHA1 wants twenty bytes, and nothing else states a width, so twenty is what gets minted. The
        // width is only observable through the refusal below, which is what proves it was not the cipher's.
        $context = $this->symmetricContext($document);
        $key = new GeneratedSessionKey($fixture->leafCertificate);
        (new Signature(new SymmetricSigningKey($key)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA1)
            ->withParts([Part::body()])($context);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is 20 bytes and this block needs exactly 32');
        (new Encryption($key))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES256_GCM)
            ->withParts([Part::body()])($context);
    }

    public function test_stating_the_width_on_the_source_lets_both_blocks_agree(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signableEnvelope();
        $context = $this->symmetricContext($document);
        $key = new GeneratedSessionKey(
            $fixture->leafCertificate,
            keyLength: DataEncryptionMethod::AES128_GCM,
        );

        // HMAC pads a short key rather than refusing it, so a signature preferring 32 bytes is content with 16.
        (new Signature(new SymmetricSigningKey($key)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption($key))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($context);

        static::assertCount(1, $this->elements($document, self::XENC, 'EncryptedKey'));
    }

    public function test_a_symmetric_key_cannot_answer_an_asymmetric_signature_method(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('RSA_SHA256 is keyed by private key material');

        (new Signature(new SymmetricSigningKey(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::RSA_SHA256)
            ->withParts([Part::body()])($this->symmetricContext($this->signableEnvelope()));
    }

    public function test_a_certificate_cannot_answer_a_keyed_mac_signature_method(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $identity = new ClientCertificate(
            $fixture->leafCertificate->contents().$fixture->leafKey->contents(),
        );

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('HMAC_SHA256 is keyed by a shared secret');

        (new Signature(new AsymmetricSigningKey($identity)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->symmetricContext($this->signableEnvelope()));
    }

    /**
     * HMAC-SHA256 is on the default allow-list, so nothing here has to name it; the profile only enters when a
     * peer asks for the SHA-1 variant.
     */
    private function symmetricContext(Document $document): WsseContext
    {
        return new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::HMAC_SHA1, SignatureMethod::HMAC_SHA256],
            )),
            new ExchangeKeys()
        );
    }

    private function signableEnvelope(): Document
    {
        return Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.self::SOAP12.'">'
            .'<soap:Header/>'
            .'<soap:Body><data>x</data></soap:Body>'
            .'</soap:Envelope>'
        );
    }
}
