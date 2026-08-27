<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification;

use Dom\Element;
use LogicException;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseKeyInfoResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OpenSslTrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\VerificationKeyExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureValidator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * The strong proof of B4: it round-trips against the B3 signer, rejects the XML-signature-wrapping and trust
 * attacks, and surfaces every failure through the single uniform exception so it cannot be used as an oracle.
 */
#[RequiresPhp('>= 8.4.21')]
final class VerifierTest extends TestCase
{
    public function test_it_verifies_a_b3_signed_body_and_reports_the_signed_element(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));

        static::assertInstanceOf(VerifiedSignature::class, $result);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertStringContainsString('WSSE Round Trip Leaf', $result->signers[0]->subjectDistinguishedName()->toString());
    }

    /**
     * The matrix is derived from the default allow-list, so admitting a new signature method to the default
     * policy forces a round-trip row for it here (an unmapped case fails loudly in the pairing helpers). The
     * keyed-MAC methods are excluded because they verify against an established secret rather than against a
     * certificate; SymmetricSignatureVerificationTest covers their round trip.
     *
     * @return iterable<string, array{0: SignatureMethod, 1: DigestMethod}>
     */
    public static function algorithmProvider(): iterable
    {
        foreach (SignatureMethod::cases() as $signatureMethod) {
            if ($signatureMethod->keyKind() === SignatureKeyKind::Hmac) {
                continue;
            }

            if (CryptoPolicy::default()->acceptsSignatureMethod($signatureMethod)) {
                yield $signatureMethod->name => [$signatureMethod, self::pairedDigest($signatureMethod)];
            }
        }
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('algorithmProvider')]
    public function test_it_verifies_each_default_accepted_signature_method(
        SignatureMethod $signatureMethod,
        DigestMethod $digestMethod,
    ): void {
        $fixture = $signatureMethod->keyKind() === SignatureKeyKind::Ecdsa
            ? WsseSignatureFixture::ecCaSignedLeaf(self::pairedCurve($signatureMethod))
            : WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()], signatureMethod: $signatureMethod, digestMethod: $digestMethod);

        $result = $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [$signatureMethod],
                acceptedDigestMethods: [$digestMethod],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        ), $this->security($document));

        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
    }

    /**
     * The matrix is derived from the default allow-list, so admitting a new canonicalization to the default
     * policy forces a round-trip row for it here.
     *
     * @return iterable<string, array{0: SignatureCanonicalization}>
     */
    public static function canonicalizationProvider(): iterable
    {
        foreach (SignatureCanonicalization::cases() as $canonicalization) {
            if (CryptoPolicy::default()->acceptsCanonicalization($canonicalization)) {
                yield $canonicalization->name => [$canonicalization];
            }
        }
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('canonicalizationProvider')]
    public function test_it_verifies_each_default_accepted_canonicalization(
        SignatureCanonicalization $canonicalization,
    ): void {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()], canonicalization: $canonicalization);

        $result = $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
                acceptedDigestMethods: [DigestMethod::SHA256],
                acceptedCanonicalizations: [$canonicalization],
            ),
        ), $this->security($document));

        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
    }

    private static function pairedDigest(SignatureMethod $method): DigestMethod
    {
        return match ($method) {
            SignatureMethod::RSA_SHA256, SignatureMethod::ECDSA_SHA256 => DigestMethod::SHA256,
            SignatureMethod::RSA_SHA384, SignatureMethod::ECDSA_SHA384 => DigestMethod::SHA384,
            SignatureMethod::RSA_SHA512, SignatureMethod::ECDSA_SHA512 => DigestMethod::SHA512,
            SignatureMethod::RSA_SHA1, SignatureMethod::DSA_SHA1 => DigestMethod::SHA1,
        };
    }

    /**
     * @return non-empty-string
     */
    private static function pairedCurve(SignatureMethod $method): string
    {
        return match ($method) {
            SignatureMethod::ECDSA_SHA256 => 'prime256v1',
            SignatureMethod::ECDSA_SHA384 => 'secp384r1',
            SignatureMethod::ECDSA_SHA512 => 'secp521r1',
            default => throw new LogicException(sprintf('No curve is paired with %s.', $method->name)),
        };
    }

    public function test_it_accepts_a_legacy_rsa_sha1_signature_only_when_the_policy_allows_it(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign(
            [WsseSignatureFixture::bodyTarget()],
            signatureMethod: SignatureMethod::RSA_SHA1,
            digestMethod: DigestMethod::SHA1,
        );

        $result = $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA1],
                acceptedDigestMethods: [DigestMethod::SHA1],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        ), $this->security($document));

        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
    }

    public function test_it_verifies_a_signed_timestamp(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::timestampTarget()], withTimestamp: true);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));

        static::assertTrue($result->signedElements->wasSigned($this->timestamp($document)));
    }

    public function test_it_verifies_the_body_and_the_timestamp_together(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget(), WsseSignatureFixture::timestampTarget()], withTimestamp: true);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));

        static::assertCount(2, $result->signedElements->signedIds());
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertTrue($result->signedElements->wasSigned($this->timestamp($document)));
    }

    public function test_was_signed_uses_object_identity_not_structural_equality(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));

        // A structurally identical clone is a different object, so it is not the signed instance.
        $clone = $this->body($document)->cloneNode(true);
        static::assertInstanceOf(Element::class, $clone);
        static::assertNotSame($this->body($document), $clone);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
        static::assertFalse($result->signedElements->wasSigned($clone));
    }

    public function test_it_rejects_a_tampered_body(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $body = $this->body($document);
        $injected = $document->toUnsafeDocument()->createElement('injected');
        $injected->textContent = 'tampered';
        $body->appendChild($injected);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
    }

    public function test_it_rejects_a_tampered_signature_value(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $signatureValue = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'SignatureValue')->item(0);
        static::assertInstanceOf(Element::class, $signatureValue);
        $signatureValue->textContent = base64_encode('forged-signature-bytes-that-will-not-verify');

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
    }

    public function test_it_rejects_a_reference_with_a_duplicate_digest_method(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $native = $document->toUnsafeDocument();
        $reference = $native->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Reference')->item(0);
        static::assertInstanceOf(Element::class, $reference);
        $duplicate = $native->createElementNS(WsseSignatureFixture::DS, 'ds:DigestMethod');
        $duplicate->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
        $reference->appendChild($duplicate);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
    }

    public function test_it_rejects_a_self_signed_signer_not_in_the_trust_store(): void
    {
        $fixture = WsseSignatureFixture::selfSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        // Anchor the trust store to a different CA, so the self-signed signer does not chain.
        $other = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($other->caCertificate), $this->security($document));
    }

    public function test_it_rejects_a_signer_chaining_to_an_unknown_ca(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $unknown = WsseSignatureFixture::caSignedLeaf();

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($unknown->caCertificate), $this->security($document));
    }

    public function test_it_rejects_an_empty_trust_store(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates(),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
                acceptedDigestMethods: [DigestMethod::SHA256],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        ), $this->security($document));
    }

    public function test_it_rejects_a_signature_method_not_in_the_allow_list(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            // The message is RSA-SHA256; the policy only accepts RSA-SHA512.
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA512],
                acceptedDigestMethods: [DigestMethod::SHA256],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        ), $this->security($document));
    }

    public function test_it_rejects_a_digest_method_not_in_the_allow_list(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($fixture->caCertificate),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
                acceptedDigestMethods: [DigestMethod::SHA512],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        ), $this->security($document));
    }

    public function test_it_rejects_an_unknown_signature_method_uri(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
        $this->rewriteAttribute($document, WsseSignatureFixture::DS, 'SignatureMethod', 'Algorithm', 'urn:made-up');

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
    }

    public function test_it_rejects_a_missing_signature(): void
    {
        $document = Document::fromXmlString(
            '<soap:Envelope xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
            .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'">'
            .'<soap:Header><wsse:Security/></soap:Header>'
            .'<soap:Body><data>x</data></soap:Body></soap:Envelope>'
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy(WsseSignatureFixture::caSignedLeaf()->caCertificate), $this->security($document));
    }

    /**
     * A second signature is one more thing that must hold, not an alternative to validate. A copy of a genuine
     * signature covers the same elements and verifies against the same key, so it changes nothing: what this
     * pins is that the verifier does not refuse the message merely for carrying two.
     */
    public function test_a_second_signature_is_verified_as_well(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->appendSignatureCopy($document, static fn (Element $copy): Element => $copy);

        $result = $this->verifier()->verify(
            $document,
            $this->policy($fixture->caCertificate),
            $this->security($document),
        );

        static::assertCount(2, $result->signers);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
    }

    /**
     * The reason a count was never the protection: an injected signature has to verify like every other one,
     * and one whose value was touched does not.
     */
    public function test_an_injected_second_signature_refuses_the_message(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->appendSignatureCopy($document, static function (Element $copy): Element {
            $value = $copy->getElementsByTagNameNS(WsseSignatureFixture::DS, 'SignatureValue')->item(0);
            self::assertInstanceOf(Element::class, $value);
            $encoded = trim($value->textContent);
            $value->textContent = ($encoded[0] === 'A' ? 'B' : 'A').substr($encoded, 1);

            return $copy;
        });

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
    }

    /**
     * Where trust is anchored on a CA rather than pinned to the peer, anyone that CA issued a certificate to can
     * produce a signature this verifier accepts. Merging their coverage with the peer's would let them satisfy
     * a requirement the peer never met, so a scope signed by two identities is refused rather than merged.
     *
     * Neither of these two endorses the other: both cover the Body, so both contribute coverage. An endorsement
     * covers a signature and nothing else, and is the one thing a second party in a scope may legitimately be.
     */
    public function test_a_scope_signed_by_two_different_signers_is_refused(): void
    {
        $peer = WsseSignatureFixture::caSignedLeaf();
        $document = $peer->sign([WsseSignatureFixture::bodyTarget()]);

        // A second signature over the same Body by a different leaf, which is what anyone holding a certificate
        // the anchor issued can produce. Named by Subject Key Identifier so it needs no token of its own.
        $other = WsseSignatureFixture::caSignedLeaf();
        $other->sign(
            [WsseSignatureFixture::bodyTarget()],
            keyIdentifier: new X509SubjectKeyIdentifier($other->leafCertificate),
            document: $document,
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->expectExceptionMessage('more than one party');
        $this->verifier()->verify(
            $document,
            new VerificationPolicy(
                trustStore: TrustStore::fromCertificates(
                    $peer->caCertificate,
                    $other->caCertificate,
                    $other->leafCertificate,
                ),
                crypto: CryptoPolicy::default(),
            ),
            $this->security($document),
        );
    }

    /**
     * @param callable(Element): Element $mangle
     */
    private function appendSignatureCopy(Document $document, callable $mangle): void
    {
        $security = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::WSSE, 'Security')->item(0);
        static::assertInstanceOf(Element::class, $security);
        $signature = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::DS, 'Signature')->item(0);
        static::assertInstanceOf(Element::class, $signature);

        $copy = $signature->cloneNode(true);
        static::assertInstanceOf(Element::class, $copy);
        $security->appendChild($mangle($copy));
    }

    public function test_a_relocated_signed_element_is_resolved_by_id_so_a_wrapper_copy_is_not_signed(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $dom = $document->toUnsafeDocument();
        $body = $this->body($document);
        $signedId = $body->getAttributeNS(WsseSignatureFixture::WSU, 'Id');

        // Relocate a structurally identical copy of the signed Body into a wrapper elsewhere in the message,
        // carrying a different id. The original signed Body is left untouched.
        $header = $dom->getElementsByTagNameNS(WsseSignatureFixture::SOAP, 'Header')->item(0);
        static::assertInstanceOf(Element::class, $header);
        $wrapper = $dom->createElement('wrapper');
        $copy = $body->cloneNode(true);
        static::assertInstanceOf(Element::class, $copy);
        $copy->setAttributeNS(WsseSignatureFixture::WSU, 'wsu:Id', 'wrapped-copy');
        $wrapper->appendChild($copy);
        $header->appendChild($wrapper);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));

        // The original id still resolves to the original element, and the wrapper copy was never signed.
        static::assertContains($signedId, $result->signedElements->signedIds());
        static::assertFalse($result->signedElements->wasSigned($copy));
    }

    public function test_a_duplicate_wsu_id_is_rejected(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $dom = $document->toUnsafeDocument();
        $body = $this->body($document);
        $signedId = $body->getAttributeNS(WsseSignatureFixture::WSU, 'Id');

        // A second element claiming the signed id makes the reference ambiguous.
        $twin = $dom->createElement('twin');
        $twin->setAttributeNS(WsseSignatureFixture::WSU, 'wsu:Id', $signedId);
        $body->appendChild($twin);

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
    }

    /**
     * Every failure path raises the same exception type, so a caller cannot tell which check failed.
     */
    public function test_all_failure_modes_share_one_exception_type(): void
    {
        $thrown = [];

        $cases = [
            'missing signature' => function (): void {
                $document = Document::fromXmlString(
                    '<soap:Envelope xmlns:soap="'.WsseSignatureFixture::SOAP.'"'
                    .' xmlns:wsse="'.WsseSignatureFixture::WSSE.'">'
                    .'<soap:Header><wsse:Security/></soap:Header><soap:Body/></soap:Envelope>'
                );
                $this->verifier()->verify($document, $this->policy(WsseSignatureFixture::caSignedLeaf()->caCertificate), $this->security($document));
            },
            'untrusted signer' => function (): void {
                $fixture = WsseSignatureFixture::caSignedLeaf();
                $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
                $this->verifier()->verify($document, $this->policy(WsseSignatureFixture::caSignedLeaf()->caCertificate), $this->security($document));
            },
            'tampered body' => function (): void {
                $fixture = WsseSignatureFixture::caSignedLeaf();
                $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
                $this->body($document)->setAttribute('tampered', 'yes');
                $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
            },
            'disallowed algorithm' => function (): void {
                $fixture = WsseSignatureFixture::caSignedLeaf();
                $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
                $this->verifier()->verify($document, new VerificationPolicy(
                    trustStore: TrustStore::fromCertificates($fixture->caCertificate),
                    crypto: new CryptoPolicy(
                        acceptedSignatureMethods: [SignatureMethod::RSA_SHA512],
                        acceptedDigestMethods: [DigestMethod::SHA256],
                        acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
                    ),
                ), $this->security($document));
            },
        ];

        foreach ($cases as $name => $case) {
            try {
                $case();
                static::fail(sprintf('Case "%s" did not fail.', $name));
            } catch (Throwable $exception) {
                $thrown[$name] = $exception::class;
            }
        }

        static::assertSame(
            array_fill_keys(array_keys($cases), SignatureVerificationFailed::class),
            $thrown,
        );
    }

    /**
     * A signature that pins prefixes can only verify if the PrefixList it declares is the one its digests were
     * actually computed under: the verifier re-canonicalizes from the declaration, so any drift between the two
     * changes the bytes and fails the digest. Asserting a non-empty list was emitted keeps the round trip from
     * passing as the feature being off.
     */
    public function test_it_verifies_a_signature_that_pins_its_inclusive_prefixes(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()], inclusivePrefixes: true);

        $prefixLists = $this->prefixLists($document);
        static::assertNotSame([], $prefixLists);
        static::assertNotContains('', $prefixLists);

        $result = $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));

        static::assertInstanceOf(VerifiedSignature::class, $result);
        static::assertTrue($result->signedElements->wasSigned($this->body($document)));
    }

    public function test_a_signature_whose_pinned_prefixes_are_rewritten_no_longer_verifies(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()], inclusivePrefixes: true);

        $this->rewriteAttribute(
            $document,
            SignatureCanonicalization::EXC_C14N->value,
            'InclusiveNamespaces',
            'PrefixList',
            'wsu',
        );

        $this->expectException(SignatureVerificationFailed::class);
        $this->verifier()->verify($document, $this->policy($fixture->caCertificate), $this->security($document));
    }

    /**
     * @return list<string>
     */
    private function prefixLists(Document $document): array
    {
        $lists = [];
        $elements = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(SignatureCanonicalization::EXC_C14N->value, 'InclusiveNamespaces');
        foreach ($elements as $element) {
            $lists[] = $element->getAttribute('PrefixList');
        }

        return $lists;
    }

    private function policy(Certificate $anchor): VerificationPolicy
    {
        return new VerificationPolicy(
            trustStore: TrustStore::fromCertificates($anchor),
            crypto: new CryptoPolicy(
                acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
                acceptedDigestMethods: [DigestMethod::SHA256],
                acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
            ),
        );
    }

    private function verifier(): Verifier
    {
        $canonicalizer = new DomCanonicalizer();

        return new Verifier(
            new SignatureLocator(),
            new SignedInfoParser(),
            new AlgorithmPolicyEnforcer(),
            new VerificationKeyExtractor(new WsseKeyInfoResolver(), (new WsuIdConvention())->lookup()),
            new ReferenceResolver((new WsuIdConvention())->lookup()),
            new DigestVerifier($canonicalizer, new Digest()),
            new SignatureValidator($canonicalizer, new OpenSslSigner()),
            new OpenSslTrustResolver(new CertificateTrust()),
        );
    }

    /**
     * The Security header addressed to the ultimate receiver. The scope the WSSE block resolves and hands the
     * verifier, so these tests verify the same region production does.
     */
    private function security(Document $document): Element
    {
        $security = SecurityHeader::locate($document, SoapVersion::fromDocument($document));
        static::assertInstanceOf(Element::class, $security);

        return $security;
    }

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(WsseSignatureFixture::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }

    private function timestamp(Document $document): Element
    {
        $timestamp = $document->toUnsafeDocument()
            ->getElementsByTagNameNS(WsseSignatureFixture::WSU, 'Timestamp')->item(0);
        static::assertInstanceOf(Element::class, $timestamp);

        return $timestamp;
    }

    private function rewriteAttribute(
        Document $document,
        string $namespace,
        string $localName,
        string $attribute,
        string $value,
    ): void {
        $element = $document->toUnsafeDocument()->getElementsByTagNameNS($namespace, $localName)->item(0);
        static::assertInstanceOf(Element::class, $element);
        $element->setAttribute($attribute, $value);
    }
}
