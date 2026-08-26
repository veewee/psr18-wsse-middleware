<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
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
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing\Symmetric;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
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

        (Decrypt::fromEstablishedKeys())($this->context($document, $keys));

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
        (Decrypt::fromEstablishedKeys())($this->context($document, new ExchangeKeys()));
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
