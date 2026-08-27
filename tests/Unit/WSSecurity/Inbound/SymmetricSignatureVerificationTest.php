<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Decrypt;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\GeneratedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing\Symmetric;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use VeeWee\Xml\Dom\Document;

/**
 * The inbound half of a symmetric binding: a signature keyed by a secret this exchange established, and
 * content encrypted under it with no xenc:EncryptedKey in sight.
 *
 * The messages are produced by this package's own outbound blocks over the exchange's key bag, which is what a
 * correlated response looks like: the peer keyed its answer with the key the request conveyed. Interop against
 * a WSS4J endpoint is covered by the java-interop harness.
 */
#[RequiresPhp('>= 8.4.21')]
final class SymmetricSignatureVerificationTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';

    public function test_it_verifies_a_signature_keyed_by_a_secret_this_exchange_established(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->symmetricallySigned($fixture, $keys);

        // No exception: the reference resolves to the established secret, the method matches its kind, and the
        // MAC checks out.
        $this->verifier($fixture)($this->context($document, $keys));

        static::assertCount(1, $this->elements($document, self::DS, 'Signature'));
    }

    public function test_an_exchange_keyed_signature_verifies_with_no_trust_store_at_all(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->symmetricallySigned($fixture, $keys);

        // A MAC names no certificate, so a deployment that only ever receives one has no anchors to offer.
        // Handing it a trust store it never reads would say it accepts something it does not.
        (new VerifySignature(useEstablishedKey: true, signed: [Part::body()]))($this->context($document, $keys));

        static::assertCount(1, $this->elements($document, self::DS, 'Signature'));
    }

    public function test_verifying_against_nothing_is_refused_where_it_is_written(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('verified against something');

        new VerifySignature();
    }

    public function test_a_signature_naming_a_secret_this_exchange_never_established_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $this->symmetricallySigned($fixture, new ExchangeKeys());

        // A fresh bag: the same message, and nothing in it names a key this exchange holds. No fallback, no
        // second attempt with another key.
        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, new ExchangeKeys()));
    }

    /**
     * The algorithm-confusion forgery, in the direction that matters: an HMAC method whose ds:KeyInfo names a
     * certificate would be verified against public key bytes anyone holds.
     */
    public function test_an_hmac_signature_naming_a_certificate_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->symmetricallySigned($fixture, $keys);

        // Swap the EncryptedKeySHA1 reference for the certificate the peer also carries, leaving the HMAC
        // method in place. A verifier deciding by the key it found rather than by the method would accept it.
        $this->replaceSignatureKeyInfo(
            $document,
            '<wsse:SecurityTokenReference'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'"'
            .' xmlns:ds="'.self::DS.'">'
            .'<ds:X509Data><ds:X509Certificate>'
            .$fixture->certificateBase64Der($fixture->leafCertificate)
            .'</ds:X509Certificate></ds:X509Data>'
            .'</wsse:SecurityTokenReference>',
        );

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, $keys));
    }

    /**
     * The mirror image: an asymmetric method answered with a secret would skip the trust decision entirely.
     */
    public function test_an_asymmetric_signature_naming_an_established_secret_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->symmetricallySigned($fixture, $keys);

        $method = $this->signatureChild($document, 'SignatureMethod');
        $method->setAttribute('Algorithm', SignatureMethod::RSA_SHA256->value);

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, $keys));
    }

    public function test_a_truncated_mac_length_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->symmetricallySigned($fixture, $keys);

        $method = $this->signatureChild($document, 'SignatureMethod');
        $length = $document->toUnsafeDocument()->createElementNS(self::DS, 'ds:HMACOutputLength');
        $length->textContent = '8';
        $method->appendChild($length);

        $this->expectException(SecurityFault::class);
        $this->verifier($fixture)($this->context($document, $keys));
    }

    public function test_a_registered_signer_check_is_refused_rather_than_skipped(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $this->symmetricallySigned($fixture, $keys);

        $block = $this->verifier($fixture)->onTrustedSigner(static function (TrustedSigner $signer): void {
            // Never reached: a keyed MAC names no signer, and a check that silently does not run is worse
            // than none at all.
        });

        $this->expectException(SecurityFault::class);
        $block($this->context($document, $keys));
    }

    /**
     * A MAC names no certificate, so the same-signer rule sees one signer in a scope where two parties
     * contributed coverage. What a caller reads as "the Body and the Timestamp were signed" would be one part
     * from the peer and one from whoever else the anchor issued a certificate to.
     */
    public function test_a_certificate_covering_a_part_the_mac_left_out_is_refused(): void
    {
        $peer = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $peer->envelope(withTimestamp: true);

        // The peer MACs the Body alone, keyed by the secret this exchange established.
        (new Signature(new Symmetric(new GeneratedSessionKey($peer->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, $keys));

        // The Timestamp is nobody's until someone signs it, and anyone the anchor issued a certificate to can.
        $attacker = $this->appendSignatureBy($document, [WsseSignatureFixture::timestampTarget()]);

        $this->assertRefusedBecause(
            'The scope carries signatures from more than one party.',
            fn (): mixed => (new VerifySignature(
                TrustStore::fromCertificates(
                    $peer->caCertificate,
                    $attacker->caCertificate,
                    $attacker->leafCertificate,
                ),
                signed: [Part::body(), Part::timestamp()],
                useEstablishedKey: true,
            ))($this->context($document, $keys)),
        );
    }

    /**
     * The same laundering against a token the attacker wrote themselves, which is what makes
     * securityHeaderContents() the requirement it looks like: every element in the header is signed, and one of
     * them is signed by the party that put it there.
     */
    public function test_a_certificate_covering_a_token_it_appended_itself_is_refused(): void
    {
        $peer = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $peer->envelope(withTimestamp: true);

        (new Signature(new Symmetric(new GeneratedSessionKey($peer->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body(), Part::securityHeaderContents()])($this->context($document, $keys));

        $token = $document->toUnsafeDocument()->createElementNS(
            WsseSignatureFixture::WSSE,
            'wsse:BinarySecurityToken',
        );
        $token->setAttributeNS(WsseSignatureFixture::WSU, 'wsu:Id', 'AppendedToken');
        $token->setAttribute('ValueType', WsseSignatureFixture::X509_TOKEN);
        $token->textContent = 'YXBwZW5kZWQ=';
        $peer->security($document)->appendChild($token);

        $attacker = $this->appendSignatureBy($document, [Target::byId('AppendedToken')]);

        $this->assertRefusedBecause(
            'The scope carries signatures from more than one party.',
            fn (): mixed => (new VerifySignature(
                TrustStore::fromCertificates(
                    $peer->caCertificate,
                    $attacker->caCertificate,
                    $attacker->leafCertificate,
                ),
                signed: [Part::body(), Part::securityHeaderContents()],
                useEstablishedKey: true,
            ))($this->context($document, $keys)),
        );
    }

    /**
     * A second signature by a certificate, over targets of its own, referenced by Subject Key Identifier so it
     * needs no token in the document. Returns the fixture it was made with, whose anchors the caller has to
     * trust for the signature to resolve at all.
     *
     * @param non-empty-list<Target> $targets
     */
    private function appendSignatureBy(Document $document, array $targets): WsseSignatureFixture
    {
        $other = WsseSignatureFixture::caSignedLeaf();
        $other->sign(
            $targets,
            keyIdentifier: new X509SubjectKeyIdentifier($other->leafCertificate),
            document: $document,
        );

        return $other;
    }

    /**
     * @param callable(): mixed $verification
     */
    private function assertRefusedBecause(string $reason, callable $verification): void
    {
        try {
            $verification();
        } catch (SecurityFault $fault) {
            static::assertSame($reason, $fault->getPrevious()?->getMessage());

            return;
        }

        static::fail('The message was accepted.');
    }

    public function test_it_decrypts_a_body_encrypted_under_the_established_key_with_no_wrapped_key(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope(body: '<data>secret</data>');
        $context = $this->context($document, $keys);
        $key = new GeneratedSessionKey($fixture->leafCertificate);

        // Signed as well as encrypted, so the key is shared and the reference list stands beside it rather than
        // inside it. That is the shape a correlated response takes: the list and the ciphertext survive the key
        // element being gone, because each xenc:EncryptedData names the key itself.
        (new Signature(new Symmetric($key)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption($key))->withParts([Part::body()])($context);

        // What a correlated response looks like: the key was conveyed by the request, so the answer carries
        // only the ciphertext and a reference naming the key.
        $encryptedKey = $this->only($document, self::XENC, 'EncryptedKey');
        $encryptedKey->parentNode?->removeChild($encryptedKey);
        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedKey'));
        static::assertCount(1, $this->elements($document, self::XENC, 'ReferenceList'));

        (new Decrypt(useEstablishedKey: true))($this->context($document, $keys));

        static::assertCount(0, $this->elements($document, self::XENC, 'EncryptedData'));
        static::assertStringContainsString('<data>secret</data>', $document->toXmlString());
    }

    public function test_a_body_naming_a_key_this_exchange_never_established_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope(body: '<data>secret</data>');
        $context = $this->context($document, new ExchangeKeys());
        $key = new GeneratedSessionKey($fixture->leafCertificate);

        (new Signature(new Symmetric($key)))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Encryption($key))->withParts([Part::body()])($context);
        $encryptedKey = $this->only($document, self::XENC, 'EncryptedKey');
        $encryptedKey->parentNode?->removeChild($encryptedKey);

        $this->expectException(SecurityFault::class);
        (new Decrypt(useEstablishedKey: true))($this->context($document, new ExchangeKeys()));
    }

    /**
     * The outbound blocks, run over one exchange bag, so the document that comes back is signed by a secret
     * that bag holds.
     */
    private function symmetricallySigned(WsseSignatureFixture $fixture, ExchangeKeys $keys): Document
    {
        $document = $fixture->envelope();

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, $keys));

        return $document;
    }

    private function verifier(WsseSignatureFixture $fixture): VerifySignature
    {
        return new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
            useEstablishedKey: true,
        );
    }

    private function context(Document $document, ExchangeKeys $keys): WsseContext
    {
        return new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::HMAC_SHA256, SignatureMethod::RSA_SHA256],
            )),
            $keys,
        );
    }

    private function signatureChild(Document $document, string $localName): Element
    {
        $element = $this->only($document, self::DS, 'Signature')
            ->getElementsByTagNameNS(self::DS, $localName)
            ->item(0);
        static::assertInstanceOf(Element::class, $element);

        return $element;
    }

    private function replaceSignatureKeyInfo(Document $document, string $replacement): void
    {
        $keyInfo = $this->only($document, self::DS, 'Signature')
            ->getElementsByTagNameNS(self::DS, 'KeyInfo')
            ->item(0);
        static::assertInstanceOf(Element::class, $keyInfo);
        $fragment = Document::fromXmlString($replacement)->locateDocumentElement();
        $imported = $document->toUnsafeDocument()->importNode($fragment, true);

        while ($keyInfo->firstChild !== null) {
            $keyInfo->removeChild($keyInfo->firstChild);
        }

        $keyInfo->appendChild($imported);
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
