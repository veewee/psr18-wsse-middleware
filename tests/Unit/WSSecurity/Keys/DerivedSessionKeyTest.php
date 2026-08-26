<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Keys;

use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\OpenSSL\PSHA1;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\DerivedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
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
 * The sp:RequireDerivedKeys shape: two wsc:DerivedKeyToken off one xenc:EncryptedKey, which falls out of two
 * DerivedSessionKey objects over one WrappedSessionKey rather than out of any keyword.
 */
#[RequiresPhp('>= 8.4.21')]
final class DerivedSessionKeyTest extends TestCase
{
    private const WSC = 'http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512';
    private const WSC_2005_02 = 'http://schemas.xmlsoap.org/ws/2005/02/sc';
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_two_derived_keys_over_one_wrapped_key_write_two_tokens_and_one_encrypted_key(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);
        $shared = new WrappedSessionKey($fixture->leafCertificate);

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey($shared))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption(new DerivedSessionKey($shared)))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($context);

        static::assertCount(1, $this->elements($document, self::XENC, 'EncryptedKey'));
        static::assertCount(2, $this->elements($document, self::WSC, 'DerivedKeyToken'));
    }

    public function test_each_token_derives_the_length_its_own_block_asked_for(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);
        $shared = new WrappedSessionKey($fixture->leafCertificate);

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey($shared))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption(new DerivedSessionKey($shared)))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($context);

        $lengths = [];
        foreach ($this->elements($document, self::WSC, 'Length') as $length) {
            $lengths[] = $length->textContent;
        }

        // Thirty-two for the MAC, sixteen for the cipher. Neither number is stated in the wiring: each follows
        // from the algorithm its own block runs.
        static::assertSame(['32', '16'], $lengths);
    }

    public function test_every_token_carries_a_fresh_nonce(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);
        $shared = new WrappedSessionKey($fixture->leafCertificate);

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey($shared))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption(new DerivedSessionKey($shared)))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($context);

        $nonces = [];
        foreach ($this->elements($document, self::WSC, 'Nonce') as $nonce) {
            $nonces[] = $nonce->textContent;
        }

        static::assertCount(2, $nonces);
        static::assertNotSame($nonces[0], $nonces[1]);
    }

    /**
     * The header order a receiver processes top-down: the key, the tokens derived from it, the list of what
     * those tokens open, then the signature.
     */
    public function test_a_derived_token_follows_the_key_it_derives_from(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);
        $shared = new WrappedSessionKey($fixture->leafCertificate);

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey($shared))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption(new DerivedSessionKey($shared)))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($context);

        $order = [];
        foreach ($fixture->security($document)->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        // The fixture's envelope already carries the peer's own token, which the profile ranks first.
        static::assertSame(
            [
                'BinarySecurityToken',
                'EncryptedKey',
                'DerivedKeyToken',
                'DerivedKeyToken',
                'ReferenceList',
                'Signature',
            ],
            $order,
        );
    }

    public function test_the_token_points_at_the_key_it_derives_from(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey(
            new WrappedSessionKey($fixture->leafCertificate),
        ))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document));

        $token = $this->only($document, self::WSC, 'DerivedKeyToken');
        static::assertSame(
            self::WSC.'/dk/p_sha1',
            $token->getAttribute('Algorithm'),
        );
        static::assertSame(
            1,
            $token->getElementsByTagNameNS(self::WSSE, 'SecurityTokenReference')->count(),
        );

        // The signature names the token, not the key the token derived from.
        $reference = $this->only($document, self::DS, 'Signature')
            ->getElementsByTagNameNS(self::WSSE, 'Reference')
            ->item(0);
        static::assertInstanceOf(Element::class, $reference);
        static::assertSame('#'.$token->getAttributeNS(self::WSU, 'Id'), $reference->getAttribute('URI'));
    }

    /**
     * A reference to the token declares the token's own type, and it is dialect-specific. A receiver enforcing
     * the Basic Security Profile classifies a reference by that and refuses one it cannot classify.
     */
    public function test_a_reference_to_the_token_declares_its_dialect_specific_type(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey(
            new WrappedSessionKey($fixture->leafCertificate),
        ))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document));

        $reference = $this->only($document, self::DS, 'Signature')
            ->getElementsByTagNameNS(self::WSSE, 'Reference')
            ->item(0);
        static::assertInstanceOf(Element::class, $reference);
        static::assertSame(self::WSC.'/dk', $reference->getAttribute('ValueType'));
    }

    public function test_the_children_are_emitted_in_schema_order(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey(
            new WrappedSessionKey($fixture->leafCertificate),
        ))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document));

        $order = [];
        foreach ($this->only($document, self::WSC, 'DerivedKeyToken')->childNodes as $child) {
            if ($child instanceof Element) {
                $order[] = $child->localName;
            }
        }

        static::assertSame(['SecurityTokenReference', 'Offset', 'Length', 'Label', 'Nonce'], $order);
    }

    public function test_the_profile_decides_which_dialect_is_emitted(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(
                crypto: new CryptoPolicy(acceptedSignatureMethods: [SignatureMethod::HMAC_SHA256]),
                wsSecureConversation: WsSecureConversationVersion::V2005_02,
            ),
            new ExchangeKeys()
        );

        (new Signature(new SymmetricSigningKey(new DerivedSessionKey(
            new WrappedSessionKey($fixture->leafCertificate),
        ))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);

        static::assertCount(0, $this->elements($document, self::WSC, 'DerivedKeyToken'));
        $token = $this->only($document, self::WSC_2005_02, 'DerivedKeyToken');
        static::assertSame(self::WSC_2005_02.'/dk/p_sha1', $token->getAttribute('Algorithm'));
    }

    public function test_a_derived_key_cannot_derive_from_another_derived_key(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('cannot be derived from another derived key');

        new DerivedSessionKey(new DerivedSessionKey(new WrappedSessionKey($fixture->leafCertificate)));
    }

    public function test_a_key_narrower_than_the_floor_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('at least 16 bytes');

        (new DerivedSessionKey(new WrappedSessionKey($fixture->leafCertificate)))
            ->resolve($this->context($document), KeyRequest::exactly(8));
    }

    public function test_two_blocks_sharing_one_derived_key_of_disagreeing_width_are_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);
        $derived = new DerivedSessionKey(new WrappedSessionKey($fixture->leafCertificate));

        (new Signature(new SymmetricSigningKey($derived)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Give each block a derived key of its own');
        (new Encryption($derived))
            ->withDataEncryptionMethod(DataEncryptionMethod::AES128_GCM)
            ->withParts([Part::body()])($context);
    }

    private function context(Document $document, ?ExchangeKeys $keys = null): WsseContext
    {
        return new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::HMAC_SHA256],
            )),
            $keys ?? new ExchangeKeys(),
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
    public function test_an_offset_below_zero_is_refused_where_it_is_written(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('must not be negative');

        new DerivedSessionKey(new WrappedSessionKey($fixture->leafCertificate), offset: -1);
    }

    public function test_an_offset_past_what_a_derivation_generates_is_refused_where_it_is_written(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('generates');

        new DerivedSessionKey(
            new WrappedSessionKey($fixture->leafCertificate),
            offset: PSHA1::MAX_GENERATED,
        );
    }
}
