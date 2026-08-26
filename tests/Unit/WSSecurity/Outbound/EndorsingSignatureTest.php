<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use LogicException;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\WrappedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\CertificateSigningKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
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
 * An endorsing supporting token: a second signature over the whole primary ds:Signature, which is what makes a
 * request protected by a wrapped session key authenticate anybody. The session key was minted locally and
 * wrapped under a public certificate, so a signature keyed by it proves possession of nothing; the endorsement
 * is what a certificate the client controls contributes.
 */
#[RequiresPhp('>= 8.4.21')]
final class EndorsingSignatureTest extends TestCase
{
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const WSU = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';

    public function test_an_endorsing_signature_covers_the_whole_primary_signature(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);

        (new Signature(new SymmetricSigningKey(new WrappedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);

        $primary = $this->signatures($document)[0];

        (new Signature(new CertificateSigningKey($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $signatures = $this->signatures($document);
        static::assertCount(2, $signatures);

        // The endorsement's one reference names the primary signature by the id it was stamped with.
        $endorsing = $signatures[1];
        $references = $endorsing->getElementsByTagNameNS(self::DS, 'Reference');
        static::assertSame(1, $references->count());
        static::assertSame(
            '#'.$primary->getAttributeNS(self::WSU, 'Id'),
            $references->item(0)?->getAttribute('URI'),
        );
    }

    /**
     * Being endorsed stamps a wsu:Id on the primary ds:Signature. That attribute is inside the element the
     * endorsement digests and outside everything the primary signature covers, so the primary value must come
     * out unchanged.
     */
    public function test_endorsing_does_not_alter_the_primary_signature_value(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);

        (new Signature(new SymmetricSigningKey(new WrappedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);

        $before = $this->signatureValue($this->signatures($document)[0]);

        (new Signature(new CertificateSigningKey($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $primary = $this->signatures($document)[0];
        static::assertNotSame('', $primary->getAttributeNS(self::WSU, 'Id'));
        static::assertSame($before, $this->signatureValue($primary));
    }

    /**
     * Endorsing is outbound only. The verifier requires exactly one ds:Signature directly inside the header it
     * scopes to, so that a second injected one cannot offer it an alternative to validate, and an endorsed
     * message a peer sent is refused by that same rule. This pins the limitation rather than the wish.
     */
    public function test_an_endorsed_message_cannot_be_verified_inbound(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();
        $context = $this->context($document, $keys);

        (new Signature(new SymmetricSigningKey(new WrappedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Signature(new CertificateSigningKey($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()]))(
            $this->context($document, $keys),
        );
    }

    public function test_an_endorsing_block_placed_before_the_one_it_endorses_fails_loudly(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        $this->expectException(WsseHeaderException::class);
        $this->expectExceptionMessage('no ds:Signature to endorse');

        (new Signature(new CertificateSigningKey($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($this->context($document));
    }

    public function test_a_header_carrying_two_signatures_has_no_primary_one(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);

        (new Signature(new SymmetricSigningKey(new WrappedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Signature(new CertificateSigningKey($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $this->expectException(WsseHeaderException::class);
        $this->expectExceptionMessage('more than one ds:Signature');

        (new Signature(new CertificateSigningKey($this->identity($fixture), KeyRef::Thumbprint)))
            ->withParts([Part::primarySignature()])($context);
    }

    /**
     * The one dynamic part that never covers a signature: it excludes every ds:Signature in both directions, so
     * endorsing one is what primarySignature() exists for.
     */
    public function test_security_header_contents_does_not_cover_a_signature(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);

        (new Signature(new SymmetricSigningKey(new WrappedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        $primary = $this->signatures($document)[0];

        (new Signature(new CertificateSigningKey($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::securityHeaderContents()])($context);

        $endorsing = $this->signatures($document)[1];
        foreach ($endorsing->getElementsByTagNameNS(self::DS, 'Reference') as $reference) {
            static::assertNotSame(
                '#'.$primary->getAttributeNS(self::WSU, 'Id'),
                $reference->getAttribute('URI'),
            );
        }
    }

    public function test_the_primary_signature_cannot_be_encrypted(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        $this->expectException(LogicException::class);
        (new Encryption(new WrappedSessionKey($fixture->leafCertificate)))
            ->withParts([Part::primarySignature()])($this->context($document));
    }

    private function signatureValue(Element $signature): string
    {
        $value = $signature->getElementsByTagNameNS(self::DS, 'SignatureValue')->item(0);
        static::assertInstanceOf(Element::class, $value);

        return trim($value->textContent);
    }

    private function identity(WsseSignatureFixture $fixture): ClientCertificate
    {
        return new ClientCertificate($fixture->leafCertificate->contents().$fixture->leafKey->contents());
    }

    private function context(Document $document, ?ExchangeKeys $keys = null): WsseContext
    {
        return new WsseContext(
            $document,
            SoapVersion::Soap12,
            new SecurityProfile(crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::HMAC_SHA256, SignatureMethod::RSA_SHA256],
            )),
            $keys ?? new ExchangeKeys(),
        );
    }

    /** @return list<Element> */
    private function signatures(Document $document): array
    {
        $found = [];
        foreach ($document->toUnsafeDocument()->getElementsByTagNameNS(self::DS, 'Signature') as $signature) {
            $found[] = $signature;
        }

        return $found;
    }
}
