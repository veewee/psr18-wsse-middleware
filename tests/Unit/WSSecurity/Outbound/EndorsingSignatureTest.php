<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Outbound;

use Dom\Element;
use LogicException;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\GeneratedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Encryption;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\Signature;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing\Asymmetric;
use Soap\Psr18WsseMiddleware\WSSecurity\Signing\Symmetric;
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

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);

        $primary = $this->signatures($document)[0];

        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
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

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);

        $before = $this->signatureValue($this->signatures($document)[0]);

        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $primary = $this->signatures($document)[0];
        static::assertNotSame('', $primary->getAttributeNS(self::WSU, 'Id'));
        static::assertSame($before, $this->signatureValue($primary));
    }

    /**
     * The shape a CXF peer emits under sp:ProtectTokens: its endorsement covers the primary signature *and* its
     * own BinarySecurityToken, because AbstractBindingBuilder::doEndorsedSignatures() adds the BST to the
     * endorsement's reference list whenever the binding asks for token protection. A supporting token declaring
     * signed parts of its own reaches the same shape by the other route.
     *
     * So an endorsement is recognised by covering a signature that verified, not by covering only that. What
     * keeps the exemption honest is that its own coverage is not reported: the endorsed party never vouched for
     * the endorsing token, so a requirement is not satisfied by it.
     */
    public function test_an_endorsement_covering_its_own_token_as_well_is_read_as_one(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();
        $context = $this->context($document, $keys);

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);

        // The endorsement covers the primary signature and the token it is keyed by, which is the pair CXF adds.
        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature(), Part::binarySecurityToken()])($context);

        $verified = (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
            useEstablishedKey: true,
        ));
        $verified($this->context($document, $keys));

        static::assertCount(2, $this->signatures($document));
    }

    /**
     * An endorsed message verifies inbound: both signatures are checked, and what a caller may require is the
     * union of what they covered.
     */
    public function test_an_endorsed_message_verifies_inbound(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();
        $context = $this->context($document, $keys);

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body()],
            useEstablishedKey: true,
        ))($this->context($document, $keys));

        static::assertCount(2, $this->signatures($document));
    }

    /**
     * Requiring the primary signature inbound is a question with no answer once a message carries two: which of
     * them is primary is not something document order decides, and the message is a peer's to shape. So the
     * part stays outbound-only, and asking for it inbound refuses rather than picks.
     */
    public function test_requiring_the_primary_signature_inbound_is_refused_as_ambiguous(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();
        $context = $this->context($document, $keys);

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(
            TrustStore::fromCertificates($fixture->caCertificate),
            signed: [Part::body(), Part::primarySignature()],
        ))($this->context($document, $keys));
    }

    /**
     * How a caller requires that a message was endorsed at all: a signature keyed by a shared secret names
     * nobody, so a registered identity check has a signer to run against only when a certificate also signed.
     */
    public function test_a_signer_check_refuses_an_unendorsed_symmetric_message(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($this->context($document, $keys));

        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()], useEstablishedKey: true))
            ->onTrustedSigner(static function (TrustedSigner $signer): void {
            })($this->context($document, $keys));
    }

    /**
     * An "endorsement" by somebody else entirely. Where trust is anchored on a CA, anyone that CA issued a
     * certificate to can sign the peer's primary signature and cover nothing else, which is structurally what an
     * endorsement looks like. Exempting it on that shape alone would let them join the message as an accepted
     * signer, which is precisely what the one-party rule exists to refuse.
     *
     * An endorsement of a certificate-keyed signature therefore has to be by that same certificate. Only an
     * endorsement of a MAC gets the exemption unconditionally, because a MAC names nobody and there is genuinely
     * no identity to hold it against.
     */
    public function test_an_endorsement_by_a_certificate_other_than_the_signer_is_refused(): void
    {
        $peer = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $peer->envelope();
        $context = $this->context($document, $keys);

        // A certificate-keyed primary, so there is an identity for an endorsement to have to match.
        (new Signature(new Asymmetric($this->identity($peer), KeyRef::BinarySecurityToken)))
            ->withParts([Part::body()])($context);

        // A different leaf under a different anchor, covering only the primary signature.
        $other = WsseSignatureFixture::caSignedLeaf();
        (new Signature(new Asymmetric($this->identity($other), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $this->assertRefusedBecause(
            'The scope carries signatures from more than one party.',
            fn (): mixed => (new VerifySignature(
                TrustStore::fromCertificates($peer->caCertificate, $other->caCertificate),
                signed: [Part::body()],
            ))($this->context($document, $keys)),
        );
    }

    /**
     * The same shape by the same certificate is the ordinary asymmetric endorsement and stays accepted: one
     * party signed twice, which is what an endorsing supporting token belonging to the sender looks like.
     */
    public function test_an_endorsement_by_the_signer_itself_is_accepted(): void
    {
        $peer = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $peer->envelope();
        $context = $this->context($document, $keys);

        (new Signature(new Asymmetric($this->identity($peer), KeyRef::BinarySecurityToken)))
            ->withParts([Part::body()])($context);
        (new Signature(new Asymmetric($this->identity($peer), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        (new VerifySignature(
            TrustStore::fromCertificates($peer->caCertificate),
            signed: [Part::body()],
        ))($this->context($document, $keys));

        static::assertCount(2, $this->signatures($document));
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

    /**
     * The endorsement is what carries an identity here: the primary signature is keyed by a session key anyone
     * holding the recipient's certificate could have minted, so it names nobody. A registered signer check
     * therefore has exactly one signer to run against, and it is the endorser's.
     */
    public function test_the_endorser_is_the_identity_a_signer_check_sees(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();
        $context = $this->context($document, $keys);

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $seen = [];
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()], useEstablishedKey: true))
            ->onTrustedSigner(static function (TrustedSigner $signer) use (&$seen): void {
                $seen[] = $signer->subjectDistinguishedName()->toString();
            })($this->context($document, $keys));

        static::assertCount(1, $seen);
        static::assertStringContainsString('WSSE Round Trip Leaf', $seen[0]);
    }

    /**
     * A second signature is one more thing that must hold. One a peer could not have produced refuses the
     * message, which is why a count was never what made this safe.
     */
    public function test_an_endorsement_that_does_not_verify_refuses_the_message(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $keys = new ExchangeKeys();
        $document = $fixture->envelope();
        $context = $this->context($document, $keys);

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $endorsing = $this->signatures($document)[1];
        $value = $endorsing->getElementsByTagNameNS(self::DS, 'SignatureValue')->item(0);
        static::assertInstanceOf(Element::class, $value);
        $encoded = trim($value->textContent);
        $value->textContent = ($encoded[0] === 'A' ? 'B' : 'A').substr($encoded, 1);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate), signed: [Part::body()], useEstablishedKey: true))(
            $this->context($document, $keys),
        );
    }

    public function test_an_endorsing_block_placed_before_the_one_it_endorses_fails_loudly(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();

        $this->expectException(WsseHeaderException::class);
        $this->expectExceptionMessage('no ds:Signature to endorse');

        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($this->context($document));
    }

    public function test_a_header_carrying_two_signatures_has_no_primary_one(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->envelope();
        $context = $this->context($document);

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
            ->withParts([Part::primarySignature()])($context);

        $this->expectException(WsseHeaderException::class);
        $this->expectExceptionMessage('more than one ds:Signature');

        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::Thumbprint)))
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

        (new Signature(new Symmetric(new GeneratedSessionKey($fixture->leafCertificate))))
            ->withSignatureMethod(SignatureMethod::HMAC_SHA256)
            ->withParts([Part::body()])($context);
        $primary = $this->signatures($document)[0];

        (new Signature(new Asymmetric($this->identity($fixture), KeyRef::BinarySecurityToken)))
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
        (new Encryption(new GeneratedSessionKey($fixture->leafCertificate)))
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
