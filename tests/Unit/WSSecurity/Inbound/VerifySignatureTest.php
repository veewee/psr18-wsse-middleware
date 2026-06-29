<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustedSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\VerifiedReferences;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\VerifiedSignature;
use VeeWee\Xml\Dom\Document;

/**
 * The VerifySignature block drives the verifier with a policy built from the profile, then asserts every
 * required part is in the returned signed set. These tests inject a recording or throwing fake verifier; the
 * real-crypto round-trip lives in VerifySignatureRoundTripTest.
 */
final class VerifySignatureTest extends TestCase
{
    private const SOAP = 'http://www.w3.org/2003/05/soap-envelope';

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

        $this->expectNotToPerformAssertions();
        (new VerifySignature($this->trustStore(), signed: []))->withVerifier($verifier)($context);
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

    public function test_it_does_not_rewrap_unexpected_exceptions(): void
    {
        $unexpected = new RuntimeException('programming error');
        $verifier = new ThrowingVerifier($unexpected);

        $this->expectExceptionObject($unexpected);
        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($this->context());
    }

    public function test_it_builds_the_policy_from_the_default_profile(): void
    {
        $context = $this->context();
        $trustStore = $this->trustStore();
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($trustStore, signed: [Part::body()]))->withVerifier($verifier)($context);

        $policy = $verifier->lastPolicy();
        static::assertNotNull($policy);
        static::assertSame([
            SignatureMethod::RSA_SHA256,
            SignatureMethod::RSA_SHA384,
            SignatureMethod::RSA_SHA512,
            SignatureMethod::ECDSA_SHA256,
            SignatureMethod::ECDSA_SHA384,
            SignatureMethod::ECDSA_SHA512,
        ], $policy->acceptedSignatureMethods);
        static::assertSame([
            DigestMethod::SHA256,
            DigestMethod::SHA384,
            DigestMethod::SHA512,
        ], $policy->acceptedDigestMethods);
        static::assertSame(
            [SignatureCanonicalization::EXC_C14N, SignatureCanonicalization::EXC_C14N_COMMENTS],
            $policy->acceptedCanonicalizations,
        );
        static::assertSame($trustStore, $policy->trustStore);
    }

    public function test_a_custom_profile_narrows_the_accepted_algorithms(): void
    {
        $profile = new SecurityProfile(
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA512],
            acceptedDigestMethods: [DigestMethod::SHA512],
        );
        $context = $this->context($profile);
        $verifier = new RecordingVerifier($this->signed([$this->body($context->document())]));

        (new VerifySignature($this->trustStore(), signed: [Part::body()]))->withVerifier($verifier)($context);

        $policy = $verifier->lastPolicy();
        static::assertNotNull($policy);
        static::assertSame([SignatureMethod::RSA_SHA512], $policy->acceptedSignatureMethods);
        static::assertSame([DigestMethod::SHA512], $policy->acceptedDigestMethods);
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

    private function context(?SecurityProfile $profile = null): WsseContext
    {
        return new WsseContext(
            Document::fromXmlString('<soap:Envelope xmlns:soap="'.self::SOAP.'"><soap:Body><data>x</data></soap:Body></soap:Envelope>'),
            SoapVersion::Soap12,
            $profile ?? new SecurityProfile(),
        );
    }

    /**
     * @param list<Element> $elements
     */
    private function signed(array $elements): VerifiedSignature
    {
        return new VerifiedSignature(new VerifiedReferences($elements), $this->signer());
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
