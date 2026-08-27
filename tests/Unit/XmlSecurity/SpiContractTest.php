<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use Dom\Element;
use LogicException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
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
        $key = new Key('key');
        $container = $this->container();

        $request = new SigningRequest(
            container: $container,
            targets: [$target],
            signingKey: $key,
            keyIdentifier: $this->keyIdentifier(),
            signatureMethod: SignatureMethod::RSA_SHA256,
            digestMethod: DigestMethod::SHA256,
            canonicalization: SignatureCanonicalization::EXC_C14N,
        );

        static::assertSame([$target], $request->targets);
        static::assertSame($key, $request->signingKey);
        static::assertSame(SignatureMethod::RSA_SHA256, $request->signatureMethod);
    }

    public function test_encryption_request_exposes_its_inputs(): void
    {
        $target = new EncryptionTarget(Target::element('urn:example', 'Body'), EncryptionMode::Content);
        $sessionKey = SessionKey::fromBytes(str_repeat("\x2a", 32));
        $container = $this->container();

        $request = new EncryptionRequest(
            container: $container,
            targets: [$target],
            sessionKey: $sessionKey,
            dataEncryptionMethod: DataEncryptionMethod::AES256_GCM,
            keyIdentifier: $this->keyIdentifier(),
        );

        static::assertSame([$target], $request->targets);
        static::assertSame($sessionKey, $request->sessionKey);
        static::assertSame(DataEncryptionMethod::AES256_GCM, $request->dataEncryptionMethod);
    }

    public function test_decryption_request_carries_the_private_key_and_its_container(): void
    {
        $key = new Key('key');
        $container = $this->container();

        $request = new DecryptionRequest($container, $key);

        static::assertSame($key, $request->privateKey);
        // The read side names its container exactly as the write side does, so the wrapped key is looked for
        // where the caller says it is rather than anywhere in the document.
        static::assertSame($container, $request->container);
    }

    public function test_verification_policy_pairs_the_trust_store_with_the_algorithm_policy(): void
    {
        $trustStore = TrustStore::fromCertificates(new Certificate('anchor'));
        $crypto = CryptoPolicy::default();

        $policy = new VerificationPolicy($trustStore, $crypto);

        static::assertSame($trustStore, $policy->trustStore);
        static::assertSame($crypto, $policy->crypto);
    }

    public function test_verified_signature_pairs_the_signed_set_with_the_signer(): void
    {
        $references = new VerifiedReferences([]);
        $signer = new TrustedSigner(DistinguishedName::fromString('CN=test'), new Certificate('cert'));

        $signature = new VerifiedSignature($references, [$signer]);

        static::assertSame($references, $signature->signedElements);
        static::assertSame([$signer], $signature->signers);
    }

    private function container(): Element
    {
        // The DTO only stores the container element; these construction-only tests never append into it, so any
        // element serves.
        return Document::fromXmlString('<container/>')->locateDocumentElement();
    }

    private function keyIdentifier(): KeyIdentifier
    {
        return new class implements KeyIdentifier {
            public function apply(Document $document): Element
            {
                // Construction-only contract test: apply() is never invoked here.
                throw new LogicException('Not exercised by the contract test.');
            }
        };
    }
}
