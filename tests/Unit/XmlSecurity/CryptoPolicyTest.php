<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use InvalidArgumentException;
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
        // CBC carries no integrity of its own and no block ties a decrypted part to a verified signature, so
        // it joins the opt-in list rather than being the one weak algorithm accepted silently.
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES128_CBC));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES192_CBC));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_CBC));
    }

    /** A peer that can only encrypt with CBC stays reachable by naming it. */
    public function test_cbc_can_be_opted_into_for_a_peer_that_offers_nothing_better(): void
    {
        $policy = new CryptoPolicy(acceptedDataEncryptionMethods: [
            DataEncryptionMethod::AES256_GCM,
            DataEncryptionMethod::AES256_CBC,
        ]);

        static::assertTrue($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_CBC));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES128_CBC));
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
        static::assertTrue($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES128_GCM));
        static::assertTrue($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES192_GCM));
        static::assertTrue($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_GCM));
    }

    /**
     * SECURITY: only the GCM ciphers authenticate their own ciphertext, and no block ties an encrypted part
     * to a verified signature, so the docs describe narrowing the list as the way to get authenticated
     * encryption guaranteed. This pins that the escape hatch actually shuts CBC out.
     */
    public function test_narrowing_the_data_ciphers_to_gcm_rejects_every_cbc_variant(): void
    {
        $policy = new CryptoPolicy(acceptedDataEncryptionMethods: [
            DataEncryptionMethod::AES128_GCM,
            DataEncryptionMethod::AES192_GCM,
            DataEncryptionMethod::AES256_GCM,
        ]);

        static::assertTrue($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_GCM));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES128_CBC));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES192_CBC));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_CBC));
        static::assertFalse($policy->acceptsDataEncryptionMethod(DataEncryptionMethod::TRIPLEDES_CBC));
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

    public function test_the_default_accepts_exactly_the_modern_signature_methods(): void
    {
        $accepted = [
            SignatureMethod::RSA_SHA256,
            SignatureMethod::RSA_SHA384,
            SignatureMethod::RSA_SHA512,
            SignatureMethod::ECDSA_SHA256,
            SignatureMethod::ECDSA_SHA384,
            SignatureMethod::ECDSA_SHA512,
        ];

        foreach (SignatureMethod::cases() as $method) {
            static::assertSame(
                in_array($method, $accepted, true),
                CryptoPolicy::default()->acceptsSignatureMethod($method),
                $method->name,
            );
        }
    }

    public function test_the_default_accepts_exactly_the_sha2_digest_methods(): void
    {
        $accepted = [DigestMethod::SHA256, DigestMethod::SHA384, DigestMethod::SHA512];

        foreach (DigestMethod::cases() as $method) {
            static::assertSame(
                in_array($method, $accepted, true),
                CryptoPolicy::default()->acceptsDigestMethod($method),
                $method->name,
            );
        }
    }

    public function test_the_default_accepts_exactly_the_exclusive_canonicalizations(): void
    {
        $accepted = [SignatureCanonicalization::EXC_C14N, SignatureCanonicalization::EXC_C14N_COMMENTS];

        foreach (SignatureCanonicalization::cases() as $canonicalization) {
            static::assertSame(
                in_array($canonicalization, $accepted, true),
                CryptoPolicy::default()->acceptsCanonicalization($canonicalization),
                $canonicalization->name,
            );
        }
    }

    public function test_an_explicit_override_replaces_the_default_acceptance(): void
    {
        $policy = new CryptoPolicy(
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA1, SignatureMethod::RSA_SHA256],
        );

        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA1));
        static::assertTrue($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA256));
        static::assertFalse($policy->acceptsSignatureMethod(SignatureMethod::RSA_SHA384));
    }

    /** SECURITY: an empty allow-list would silently reject everything; a caller must not express it by accident. */
    public function test_an_empty_signature_allow_list_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CryptoPolicy(acceptedSignatureMethods: []);
    }

    public function test_an_empty_digest_allow_list_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CryptoPolicy(acceptedDigestMethods: []);
    }

    public function test_an_empty_canonicalization_allow_list_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CryptoPolicy(acceptedCanonicalizations: []);
    }

    public function test_an_empty_data_encryption_allow_list_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new CryptoPolicy(acceptedDataEncryptionMethods: []);
    }
}
