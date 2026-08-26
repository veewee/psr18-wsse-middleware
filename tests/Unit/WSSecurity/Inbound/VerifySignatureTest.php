<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedReferences;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use VeeWee\Xml\Dom\Document;

/**
 * The VerifySignature block drives the verifier with a policy built from the profile, then asserts every
 * required part is in the returned signed set. These tests inject a recording or throwing fake verifier; the
 * real-crypto round-trip lives in VerifySignatureRoundTripTest.
 */
final class VerifySignatureTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';
    private const WSSE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';

    public function test_it_passes_a_signed_required_body(): void
    {
        $context = $this->context();
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);
        $this->addToAssertionCount(1);
    }

    public function test_with_verifier_routes_verification_to_the_given_verifier(): void
    {
        $context = $this->context();
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);

        static::assertSame($context->document(), $verifier->lastDocument());
    }

    public function test_it_verifies_within_the_security_header_addressed_to_us(): void
    {
        $context = $this->context();
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);

        $scope = $verifier->lastScope();
        static::assertInstanceOf(Element::class, $scope);
        static::assertSame('Security', $scope->localName);
        static::assertSame(self::WSSE, $scope->namespaceURI);
    }

    public function test_a_message_with_no_security_header_for_us_is_refused(): void
    {
        // Nothing else in the envelope stands in for our header: with no scope there is no signature of ours to
        // verify, so the block refuses rather than falling back to whatever the message does carry.
        $context = new WsseContext(
            Document::fromXmlString('<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body><data>x</data></soap:Body></soap:Envelope>'),
            SoapVersion::Soap12,
            new SecurityProfile(),
            new ExchangeKeys()
        );
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        $this->expectException(SecurityFault::class);
        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);
    }

    public function test_a_security_header_addressed_to_another_hop_is_not_ours(): void
    {
        // The header exists but names an intermediary, so it is that hop's. Accepting it would verify a
        // signature made for someone else's requirements against ours.
        $context = new WsseContext(
            Document::fromXmlString(
                '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'">'
                .'<soap:Header><wsse:Security soap:role="urn:some-intermediary"/></soap:Header>'
                .'<soap:Body><data>x</data></soap:Body></soap:Envelope>'
            ),
            SoapVersion::Soap12,
            new SecurityProfile(),
            new ExchangeKeys()
        );
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        $this->expectException(SecurityFault::class);
        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);
    }

    public function test_a_profile_naming_an_actor_verifies_within_that_actors_header(): void
    {
        // Configured as a named intermediary, the header carrying our actor is the one we verify in, and the
        // untargeted header, which belongs to the ultimate receiver, is not ours to read.
        $context = new WsseContext(
            Document::fromXmlString(
                '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'"><soap:Header>'
                .'<wsse:Security><ultimate/></wsse:Security>'
                .'<wsse:Security soap:role="urn:ours"><ours/></wsse:Security>'
                .'</soap:Header><soap:Body><data>x</data></soap:Body></soap:Envelope>'
            ),
            SoapVersion::Soap12,
            new SecurityProfile(actorOrRole: 'urn:ours'),
            new ExchangeKeys()
        );
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);

        static::assertSame('ours', $verifier->lastScope()?->firstElementChild?->localName);
    }

    public function test_it_throws_a_security_fault_when_a_required_part_was_not_signed(): void
    {
        $context = $this->context();
        $verifier = new RecordingVerifier($this->signed([]));

        $this->expectException(SecurityFault::class);
        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);
    }

    public function test_an_empty_signed_list_only_requires_a_verifiable_signature(): void
    {
        $context = $this->context();
        $verifier = new RecordingVerifier($this->signed([]));

        (new VerifySignature($this->trustStore(), signed: []))->withVerifier($verifier)($context);

        // "Only" cuts both ways: no part is demanded, but the signature itself must still verify. An empty
        // signed list never bypasses verification.
        $this->expectException(SecurityFault::class);
        (new VerifySignature($this->trustStore(), signed: []))
            ->withVerifier(new ThrowingVerifier(SignatureVerificationFailed::withReason('any reason at all')))($this->context());
    }

    public function test_it_maps_a_verifier_signature_failure_to_a_security_fault(): void
    {
        $cause = SignatureVerificationFailed::withReason('bad sig');
        $verifier = new ThrowingVerifier($cause);

        try {
            (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($this->context());
            static::fail('Expected a SecurityFault.');
        } catch (SecurityFault $fault) {
            static::assertStringNotContainsString('bad sig', $fault->getMessage());
            static::assertSame($cause, $fault->getPrevious());
        }
    }

    public function test_it_maps_a_verifier_canonicalization_failure_to_a_security_fault(): void
    {
        $context = $this->context();
        $cause = CanonicalizationFailed::nativeError($this->body($context->document()), SignatureCanonicalization::EXC_C14N);
        $verifier = new ThrowingVerifier($cause);

        $this->expectException(SecurityFault::class);
        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);
    }

    public function test_it_collapses_a_foreign_verifier_exception_while_keeping_the_cause(): void
    {
        // The verifier is a replaceable seam, so a type this package never declares is what a third-party one
        // raises. Reaching the caller as itself would give a peer an outcome per implementation quirk, which is
        // what the uniform fault denies. The operator keeps everything: the original is the chained cause.
        $foreign = new RuntimeException('pki-service timeout for CN=peer.example.com');
        $verifier = new ThrowingVerifier($foreign);

        try {
            (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($this->context());
        } catch (SecurityFault $fault) {
            static::assertSame('The inbound security header could not be processed.', $fault->getMessage());
            static::assertStringNotContainsString('peer.example.com', $fault->getMessage());
            static::assertSame($foreign, $fault->getPrevious());

            return;
        }

        static::fail('Expected a SecurityFault.');
    }

    public function test_it_builds_the_policy_from_the_default_profile(): void
    {
        $profile = new SecurityProfile();
        $context = $this->context($profile);
        $trustStore = $this->trustStore();
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($trustStore, signed: [Part::body()]))->withVerifier($verifier)($context);

        // The profile's own CryptoPolicy reaches the verifier as-is: nothing is copied, so nothing can drift.
        $policy = $verifier->lastPolicy();
        static::assertNotNull($policy);
        static::assertSame($trustStore, $policy->trustStore);
        static::assertSame($profile->crypto(), $policy->crypto);
    }

    public function test_a_custom_profile_narrows_the_accepted_algorithms(): void
    {
        $crypto = new CryptoPolicy(
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA512],
            acceptedDigestMethods: [DigestMethod::SHA512],
        );
        $context = $this->context(new SecurityProfile(crypto: $crypto));
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);

        $policy = $verifier->lastPolicy();
        static::assertNotNull($policy);
        static::assertSame($crypto, $policy->crypto);
        static::assertTrue($policy->crypto->acceptsSignatureMethod(SignatureMethod::RSA_SHA512));
        static::assertFalse($policy->crypto->acceptsSignatureMethod(SignatureMethod::RSA_SHA256));
    }

    public function test_all_failure_causes_surface_one_identical_security_fault(): void
    {
        $causes = [
            'verifier-failure' => function (): void {
                $verifier = new ThrowingVerifier(SignatureVerificationFailed::withReason('bad sig'));
                (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($this->context());
            },
            'required-part-missing' => function (): void {
                $context = $this->context();
                $verifier = new RecordingVerifier($this->signed([]));
                (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);
            },
            'missing-element' => function (): void {
                $context = $this->context();
                $verifier = new RecordingVerifier($this->signed([]));
                (new VerifySignature($this->trustStore(), signed: [Part::timestamp()]))->withVerifier($verifier)($context);
            },
        ];

        $messages = [];
        $types = [];
        foreach ($causes as $name => $cause) {
            try {
                $cause();
                static::fail('Expected a failure for cause: '.$name);
            } catch (SecurityFault $fault) {
                $messages[$name] = $fault->getMessage();
                $types[$name] = $fault::class;
            }
        }

        static::assertCount(3, $messages);
        static::assertCount(1, array_unique($messages), 'Every failure cause must expose one identical message.');
        static::assertCount(1, array_unique($types), 'Every failure cause must surface the same exception type.');
    }

    /**
     * The envelope carries a Security header addressed to the ultimate receiver, because that header is the
     * scope the block resolves and verifies within. A response carrying none is refused outright, which
     * test_a_message_with_no_security_header_for_us_is_refused covers.
     */
    private function context(?SecurityProfile $profile = null): WsseContext
    {
        return new WsseContext(
            Document::fromXmlString(
                '<soap:Envelope xmlns:soap="'.self::SOAP.'" xmlns:wsse="'.self::WSSE.'">'
                .'<soap:Header><wsse:Security/></soap:Header>'
                .'<soap:Body><data>x</data></soap:Body></soap:Envelope>'
            ),
            SoapVersion::Soap12,
            $profile ?? new SecurityProfile(),
            new ExchangeKeys()
        );
    }

    /**
     * @param list<Element> $elements
     */
    private function signed(array $elements): VerifiedSignature
    {
        return new VerifiedSignature(new VerifiedReferences($elements), [$this->signer()]);
    }

    private function signer(): TrustedSigner
    {
        return new TrustedSigner(DistinguishedName::fromString('CN=test'), new Certificate('pem'));
    }

    private function trustStore(): TrustStore
    {
        return TrustStore::fromCertificates(new Certificate('anchor-pem'));
    }

    private function body(Document $document): Element
    {
        $body = $document->toUnsafeDocument()->getElementsByTagNameNS(self::SOAP, 'Body')->item(0);
        static::assertInstanceOf(Element::class, $body);

        return $body;
    }
}
