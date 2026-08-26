<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Keys;

use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\PreSharedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SymmetricSigningKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * A secret both sides already hold: nothing is conveyed, so no xenc:EncryptedKey appears in either direction and
 * the signature names the key by the identifier the two agreed on.
 */
#[RequiresPhp('>= 8.4.21')]
final class PreSharedSessionKeyTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    /** Base64, because the reference declares a base64 encoding type; a plain name is refused. */
    private const IDENTIFIER = 'dGhlLWFncmVlZC1rZXk=';
    private const VALUE_TYPE = 'urn:example:pre-shared-key';

    public function test_it_signs_without_writing_any_token(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey($this->key())))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, new ExchangeKeys()));

        // Nothing to convey, so nothing is written but the signature itself.
        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedKey'));
        static::assertCount(1, $this->elements($document, self::DS, 'Signature'));

        $keyIdentifier = $this->only($document, self::WSSE, 'KeyIdentifier');
        static::assertSame(self::VALUE_TYPE, $keyIdentifier->getAttribute('ValueType'));
        static::assertSame(self::IDENTIFIER, $keyIdentifier->textContent);
    }

    public function test_a_signature_it_produced_verifies_against_the_same_secret(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey($this->key())))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, new ExchangeKeys()));

        // A fresh exchange, as an inbound-only deployment has: the block registers the secret itself.
        $block = (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
        ))->withPreSharedKey($this->key());

        $block($this->context($document, new ExchangeKeys()));

        static::assertCount(1, $this->elements($document, self::DS, 'Signature'));
    }

    public function test_a_signature_does_not_verify_against_a_different_secret(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey($this->key())))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, new ExchangeKeys()));

        $block = (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
        ))->withPreSharedKey($this->key(str_repeat("\x2b", 32)));

        $this->expectException(SecurityFault::class);
        $block($this->context($document, new ExchangeKeys()));
    }

    public function test_a_signature_is_refused_when_no_secret_is_registered(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey($this->key())))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, new ExchangeKeys()));

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
        ))($this->context($document, new ExchangeKeys()));
    }

    public function test_it_round_trips_an_encrypted_body_with_no_wrapped_key_anywhere(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope(body: '<data>secret</data>');

        (new Encryption($this->key()))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES256_GCM)
            ->withParts([Part::body()])($this->context($document, new ExchangeKeys()));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedKey'));
        static::assertCount(1, $this->elements($document, self::XENC, 'EncryptedData'));

        // No private key: there is nothing wrapped to unwrap, in either direction.
        (new Decrypt())->withPreSharedKey($this->key())($this->context($document, new ExchangeKeys()));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedData'));
        static::assertStringContainsString('<data>secret</data>', $document->toXmlString());
    }

    public function test_a_cipher_whose_width_the_secret_cannot_serve_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is 32 bytes and this block needs exactly 16');
        (new Encryption($this->key()))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($this->context($document, new ExchangeKeys()));
    }

    /**
     * The identifier is written verbatim under the encoding the reference declares, so a plain name under the
     * base64 default is a reference saying one thing and carrying another.
     */
    public function test_an_identifier_that_is_not_base64_is_refused_under_the_base64_default(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not base64');

        new PreSharedSessionKey(
            SessionKey::fromBytes(str_repeat("\x2a", 32)),
            'the-agreed-key',
            self::VALUE_TYPE,
        );
    }

    public function test_a_peer_naming_its_own_encoding_may_use_any_identifier(): void
    {
        // The encoding is the peer's to agree, so naming a different one is what makes a plain name legitimate.
        $key = new PreSharedSessionKey(
            SessionKey::fromBytes(str_repeat("\x2a", 32)),
            'the-agreed-key',
            self::VALUE_TYPE,
            'urn:example:plain-text',
        );

        $keys = new ExchangeKeys();
        $key->resolve($this->context($this->envelopeFor(), $keys), KeyRequest::preferably(32));

        static::assertNotNull($keys->resolve('the-agreed-key'));
    }

    public function test_an_empty_secret_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must not be empty');

        new PreSharedSessionKey(SessionKey::fromBytes(''), self::IDENTIFIER, self::VALUE_TYPE);
    }

    public function test_registering_the_same_source_twice_is_a_no_op(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $key = $this->key();
        $context = $this->context($fixture->envelope(), $keys);

        $first = $key->resolve($context, KeyRequest::preferably(32));
        $second = $key->resolve($context, KeyRequest::preferably(32));

        static::assertSame($first, $second);
        static::assertSame($first->bytes, $keys->resolve(self::IDENTIFIER));
    }

    private function envelopeFor(): Document
    {
        return WsseSignatureFixture::caSignedLeaf()->envelope();
    }

    private function key(string $bytes = "\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a\x2a"): PreSharedSessionKey
    {
        return new PreSharedSessionKey(SessionKey::fromBytes($bytes), self::IDENTIFIER, self::VALUE_TYPE);
    }

    private function context(Document $document, ExchangeKeys $keys): WsseContext
    {
        return new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::HMAC_SHA256],
            )),
            $keys,
        );
    }

    /** @return list<Element> */
    private function elements(Document $document, string $namespace, string $localName): array
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName) as $element) {
            $found[] = $element;
        }

        return $found;
    }

    private function only(Document $document, string $namespace, string $localName): Element
    {
        $elements = $this->elements($document, $namespace, $localName);
        static::assertCount(1, $elements);

        return $elements[0];
    }
}
