<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\DerivedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\WrappedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SymmetricSigningKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecureConversationVersion;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * The inbound half of a derived-keys exchange: a wsc:DerivedKeyToken is re-derived from the secret its own
 * reference names, with every parameter read off the element rather than assumed.
 */
#[RequiresPhp('>= 8.4.21')]
final class DerivedKeyVerificationTest extends TestCase
{
    private const WSC = 'http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_it_verifies_a_signature_keyed_by_a_derived_key(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->signedWithADerivedKey($fixture, $keys);

        $this->verifier($fixture)($this->context($document, $keys));

        static::assertCount(1, $this->elements($document, self::WSC, 'DerivedKeyToken'));
    }

    public function test_a_tampered_nonce_derives_a_different_key_and_fails(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->signedWithADerivedKey($fixture, $keys);

        $nonce = $this->only($document, self::WSC, 'Nonce');
        $nonce->textContent = base64_encode(str_repeat("\x00", 16));

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, $keys));
    }

    public function test_a_tampered_label_derives_a_different_key_and_fails(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->signedWithADerivedKey($fixture, $keys);

        $this->only($document, self::WSC, 'Label')->textContent = 'something-else';

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, $keys));
    }

    public function test_a_length_beyond_the_cap_is_refused_before_deriving(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->signedWithADerivedKey($fixture, $keys);

        // P_SHA1 generates offset plus length bytes before slicing, so an unbounded length is a memory bomb.
        $this->only($document, self::WSC, 'Length')->textContent = '99999999';

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, $keys));
    }

    public function test_a_token_carrying_both_a_generation_and_an_offset_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->signedWithADerivedKey($fixture, $keys);

        // The two are a schema choice expressing one position, so a token carrying both describes two.
        $token = $this->only($document, self::WSC, 'DerivedKeyToken');
        $generation = $document->toUnsafeDocument()->createElementNS(self::WSC, 'wsc:Generation');
        $generation->textContent = '0';
        $token->appendChild($generation);

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, $keys));
    }

    public function test_a_token_whose_reference_names_nothing_established_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->signedWithADerivedKey($fixture, new ExchangeKeys());

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, new ExchangeKeys()));
    }

    public function test_the_2005_02_dialect_is_read_too(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey(
            new WrappedSessionKey($fixture->leafCertificate),
        ))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])(new WsseContext(
                $document,
                SoapVersion::Soap12,
                new SecurityProfile(
                    crypto: new CryptoPolicy(acceptedSignatureMethods: [SignatureMethod::HMAC_SHA256]),
                    wsSecureConversation: WsSecureConversationVersion::V2005_02,
                ),
                $keys,
            ));

        // The profile emitted the older dialect; the reader accepts both whatever the profile says.
        $this->verifier($fixture)($this->context($document, $keys));

        static::assertCount(1, $this->elements($document, WsSecureConversationVersion::V2005_02->value, 'DerivedKeyToken'));
    }

    public function test_it_decrypts_a_body_encrypted_under_a_derived_key(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope(body: '<data>secret</data>');
        $context = $this->context($document, $keys);

        (new Encryption(new DerivedSessionKey(new WrappedSessionKey($fixture->leafCertificate))))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($context);

        // As a correlated response would arrive: the key it derives from travelled with the request.
        $encryptedKey = $this->only($document, self::XENC, 'EncryptedKey');
        $encryptedKey->parentNode?->removeChild($encryptedKey);

        (new Decrypt())($this->context($document, $keys));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedData'));
        static::assertStringContainsString('<data>secret</data>', $document->toXmlString());
    }

    private function signedWithADerivedKey(WsseSignatureFixture $fixture, ExchangeKeys $keys): Document
    {
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey(
            new WrappedSessionKey($fixture->leafCertificate),
        ))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, $keys));

        return $document;
    }

    private function verifier(WsseSignatureFixture $fixture): VerifySignature
    {
        return new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
        );
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
