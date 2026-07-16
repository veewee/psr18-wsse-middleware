<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use Dom\Element;
use LogicException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionMode;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionTarget;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedReferences;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use VeeWee\Xml\Dom\Document;

final class SpiContractTest extends TestCase
{
    public function test_signing_request_exposes_its_inputs(): void
    {
        $target = Target::element('urn:example', 'Body');
        $certificate = new Certificate('cert');
        $key = new Key('key');

        $request = new SigningRequest(
            targets: [$target],
            signingKey: $key,
            signingCertificate: $certificate,
            keyIdentifier: $this->keyIdentifier(),
            signatureMethod: SignatureMethod::RSA_SHA256,
            digestMethod: DigestMethod::SHA256,
            canonicalization: SignatureCanonicalization::EXC_C14N,
        );

        static::assertSame([$target], $request->targets);
        static::assertSame($key, $request->signingKey);
        static::assertSame($certificate, $request->signingCertificate);
        static::assertSame(SignatureMethod::RSA_SHA256, $request->signatureMethod);
    }

    public function test_encryption_request_exposes_its_inputs(): void
    {
        $target = new EncryptionTarget(Target::element('urn:example', 'Body'), EncryptionMode::Content);
        $recipient = new Certificate('cert');

        $request = new EncryptionRequest(
            targets: [$target],
            recipientCertificate: $recipient,
            keyIdentifier: $this->keyIdentifier(),
            dataEncryptionMethod: DataEncryptionMethod::AES256_GCM,
            keyTransportAlgorithm: KeyTransportAlgorithm::oaepSha1(),
        );

        static::assertSame([$target], $request->targets);
        static::assertSame($recipient, $request->recipientCertificate);
        static::assertSame(DataEncryptionMethod::AES256_GCM, $request->dataEncryptionMethod);
    }

    public function test_decryption_request_carries_the_private_key(): void
    {
        $key = new Key('key');

        static::assertSame($key, (new DecryptionRequest($key))->privateKey);
    }

    public function test_verification_policy_holds_its_allow_lists(): void
    {
        $trustStore = TrustStore::fromCertificates(new Certificate('anchor'));

        $policy = new VerificationPolicy(
            trustStore: $trustStore,
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA256],
            acceptedDigestMethods: [DigestMethod::SHA256],
            acceptedCanonicalizations: [SignatureCanonicalization::EXC_C14N],
        );

        static::assertSame($trustStore, $policy->trustStore);
        static::assertSame([SignatureMethod::RSA_SHA256], $policy->acceptedSignatureMethods);
        static::assertSame([DigestMethod::SHA256], $policy->acceptedDigestMethods);
        static::assertSame([SignatureCanonicalization::EXC_C14N], $policy->acceptedCanonicalizations);
    }

    public function test_verified_signature_pairs_the_signed_set_with_the_signer(): void
    {
        $references = new VerifiedReferences([]);
        $signer = new TrustedSigner(DistinguishedName::fromString('CN=test'), new Certificate('cert'));

        $signature = new VerifiedSignature($references, $signer);

        static::assertSame($references, $signature->signedElements);
        static::assertSame($signer, $signature->signer);
    }

    private function keyIdentifier(): KeyIdentifier
    {
        return new class implements KeyIdentifier {
            public function apply(Document $document, Certificate $certificate): Element
            {
                // Construction-only contract test: apply() is never invoked here. Concrete strategies arrive in C2.
                throw new LogicException('Not exercised by the contract test.');
            }
        };
    }
}
