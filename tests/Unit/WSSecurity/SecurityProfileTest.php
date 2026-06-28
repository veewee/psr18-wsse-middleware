<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;

final class SecurityProfileTest extends TestCase
{
    public function test_the_default_profile_uses_strong_methods(): void
    {
        $profile = SecurityProfile::default();

        static::assertSame(300, $profile->timestampTtl());
        static::assertSame(60, $profile->clockSkew());
        static::assertSame(SignatureMethod::RSA_SHA256, $profile->signatureMethod());
        static::assertSame(DigestMethod::SHA256, $profile->digestMethod());
        static::assertSame(SignatureCanonicalization::EXC_C14N, $profile->canonicalization());
        static::assertSame(DataEncryptionMethod::AES256_GCM, $profile->dataEncryptionMethod());
        static::assertSame(KeyEncryptionMethod::RSA_OAEP, $profile->keyEncryptionMethod());
    }

    public function test_a_partial_override_keeps_secure_defaults_for_the_rest(): void
    {
        $profile = new SecurityProfile(timestampTtl: 120, signatureMethod: SignatureMethod::RSA_SHA512);

        static::assertSame(120, $profile->timestampTtl());
        static::assertSame(SignatureMethod::RSA_SHA512, $profile->signatureMethod());
        // untouched → defaults
        static::assertSame(60, $profile->clockSkew());
        static::assertSame(DigestMethod::SHA256, $profile->digestMethod());
    }

    /** SECURITY: the default allow-list rejects the weak/broken algorithms. */
    public function test_the_default_allow_list_rejects_weak_algorithms(): void
    {
        $profile = SecurityProfile::default();

        static::assertFalse($profile->acceptsSignatureMethod(SignatureMethod::RSA_SHA1));
        static::assertFalse($profile->acceptsSignatureMethod(SignatureMethod::DSA_SHA1));
        static::assertFalse($profile->acceptsDigestMethod(DigestMethod::SHA1));
        static::assertFalse($profile->acceptsDigestMethod(DigestMethod::RIPEMD160));
        static::assertFalse($profile->acceptsKeyEncryptionMethod(KeyEncryptionMethod::RSA_1_5));
        static::assertFalse($profile->acceptsDataEncryptionMethod(DataEncryptionMethod::TRIPLEDES_CBC));
    }

    /** SECURITY: the default allow-list accepts the strong algorithms. */
    public function test_the_default_allow_list_accepts_strong_algorithms(): void
    {
        $profile = SecurityProfile::default();

        static::assertTrue($profile->acceptsSignatureMethod(SignatureMethod::RSA_SHA256));
        static::assertTrue($profile->acceptsDigestMethod(DigestMethod::SHA256));
        static::assertTrue($profile->acceptsKeyEncryptionMethod(KeyEncryptionMethod::RSA_OAEP));
        static::assertTrue($profile->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_GCM));
        static::assertTrue($profile->acceptsDataEncryptionMethod(DataEncryptionMethod::AES256_CBC));
    }

    public function test_a_legacy_peer_can_be_supported_by_an_explicit_allow_list(): void
    {
        $profile = new SecurityProfile(
            acceptedSignatureMethods: [SignatureMethod::RSA_SHA1, SignatureMethod::RSA_SHA256],
        );

        static::assertTrue($profile->acceptsSignatureMethod(SignatureMethod::RSA_SHA1));
        static::assertTrue($profile->acceptsSignatureMethod(SignatureMethod::RSA_SHA256));
        static::assertFalse($profile->acceptsSignatureMethod(SignatureMethod::RSA_SHA512));
    }
}
