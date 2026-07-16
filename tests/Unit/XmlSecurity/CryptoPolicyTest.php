<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

final class CryptoPolicyTest extends TestCase
{
    public function test_the_default_policy_uses_strong_methods(): void
    {
        $policy = CryptoPolicy::default();

        static::assertSame(SignatureMethod::RSA_SHA256, $policy->signatureMethod());
        static::assertSame(DigestMethod::SHA256, $policy->digestMethod());
        static::assertSame(SignatureCanonicalization::EXC_C14N, $policy->canonicalization());
        static::assertSame(DataEncryptionMethod::AES256_GCM, $policy->dataEncryptionMethod());
        static::assertSame(KeyEncryptionMethod::RSA_OAEP, $policy->keyEncryptionMethod());
    }

    public function test_a_partial_override_keeps_secure_defaults_for_the_rest(): void
    {
        $policy = new CryptoPolicy(signatureMethod: SignatureMethod::RSA_SHA512);

        static::assertSame(SignatureMethod::RSA_SHA512, $policy->signatureMethod());
        // untouched → default
        static::assertSame(DigestMethod::SHA256, $policy->digestMethod());
    }

    /** SECURITY: the default allow-list rejects the weak/broken algorithms. */
    public function test_the_default_allow_list_rejects_weak_algorithms(): void
    {
        $policy = CryptoPolicy::default();

        static::assertFalse($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA1));
        static::assertFalse($policy->acceptsSignatureMethod(SignatureMethod::DSA_SHA1));
        static::assertFalse($policy->acceptsDigestMethod(DigestMethod::SHA1));
        static::assertFalse($policy->acceptsDigestMethod(DigestMethod::RIPEMD160));
        static::assertFalse($policy->acceptsKeyEncryptionMethod(KeyEncryptionMethod::RSA_1_5));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::TRIPLEDES_CBC));
    }

    /** SECURITY: the default allow-list accepts the strong algorithms. */
    public function test_the_default_allow_list_accepts_strong_algorithms(): void
    {
        $policy = CryptoPolicy::default();

        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA256));
        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::ECDSA_SHA256));
        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::ECDSA_SHA384));
        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::ECDSA_SHA512));
        static::assertTrue($policy->acceptsDigestMethod(DigestMethod::SHA256));
        static::assertTrue($policy->acceptsKeyEncryptionMethod(KeyEncryptionMethod::RSA_OAEP));
        static::assertTrue($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_GCM));
        static::assertTrue($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_CBC));
    }

    /** SECURITY: the default accepts both exclusive C14N variants only; inclusive C14N is opt-in. */
    public function test_the_default_accepts_both_exclusive_canonicalization_variants(): void
    {
        $policy = CryptoPolicy::default();

        static::assertTrue($policy->acceptsCanonicalization(SignatureCanonicalization::EXC_C14N));
        static::assertTrue($policy->acceptsCanonicalization(SignatureCanonicalization::EXC_C14N_COMMENTS));
        static::assertFalse($policy->acceptsCanonicalization(SignatureCanonicalization::C14N));
        static::assertFalse($policy->acceptsCanonicalization(SignatureCanonicalization::C14N_COMMENTS));
    }

    public function test_inclusive_canonicalization_can_be_opted_in_by_an_explicit_allow_list(): void
    {
        $policy = new CryptoPolicy(
            acceptedCanonicalizations: [SignatureCanonicalization::C14N, SignatureCanonicalization::EXC_C14N],
        );

        static::assertTrue($policy->acceptsCanonicalization(SignatureCanonicalization::C14N));
        static::assertTrue($policy->acceptsCanonicalization(SignatureCanonicalization::EXC_C14N));
        static::assertFalse($policy->acceptsCanonicalization(SignatureCanonicalization::C14N_COMMENTS));
        static::assertFalse($policy->acceptsCanonicalization(SignatureCanonicalization::EXC_C14N_COMMENTS));
    }

    public function test_a_legacy_peer_can_be_supported_by_an_explicit_allow_list(): void
    {
        $policy = new CryptoPolicy(
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA1, SignatureMethod::RSA_SHA256],
        );

        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA1));
        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA256));
        static::assertFalse($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA512));
    }
}
