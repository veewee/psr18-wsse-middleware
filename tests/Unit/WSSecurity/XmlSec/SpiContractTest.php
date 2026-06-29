<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\XmlSec;

use Dom\Element;
use LogicException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\DecryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing\SigningRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\VerifiedReferences;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\VerifiedSignature;
use VeeWee\Xml\Dom\Document;

final class SpiContractTest extends TestCase
{
    public function test_signing_request_exposes_its_inputs(): void
    {
        $part = Part::body();
        $certificate = new Certificate('cert');
        $key = new Key('key');

        $request = new SigningRequest(
            parts: [$part],
            signingKey: $key,
            signingCertificate: $certificate,
            keyIdentifier: $this->keyIdentifier(),
            signatureMethod: SignatureMethod::RSA_SHA256,
            digestMethod: DigestMethod::SHA256,
            canonicalization: SignatureCanonicalization::EXC_C14N,
        );

        static::assertSame([$part], $request->parts);
        static::assertSame($key, $request->signingKey);
        static::assertSame($certificate, $request->signingCertificate);
        static::assertSame(SignatureMethod::RSA_SHA256, $request->signatureMethod);
    }

    public function test_encryption_request_exposes_its_inputs(): void
    {
        $part = Part::body();
        $recipient = new Certificate('cert');

        $request = new EncryptionRequest(
            parts: [$part],
            recipientCertificate: $recipient,
            keyIdentifier: $this->keyIdentifier(),
            dataEncryptionMethod: DataEncryptionMethod::AES256_GCM,
            keyTransportAlgorithm: KeyTransportAlgorithm::oaepSha1(),
        );

        static::assertSame([$part], $request->parts);
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
