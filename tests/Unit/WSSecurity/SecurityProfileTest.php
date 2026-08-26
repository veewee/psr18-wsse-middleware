<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

final class SecurityProfileTest extends TestCase
{
    public function test_the_default_profile_uses_the_standard_freshness_window(): void
    {
        $profile = SecurityProfile::default();

        static::assertSame(300, $profile->timestampTtl());
        static::assertSame(60, $profile->clockSkew());
    }

    public function test_the_window_can_be_overridden_independently(): void
    {
        $profile = new SecurityProfile(timestampTtl: 120, clockSkew: 30);

        static::assertSame(120, $profile->timestampTtl());
        static::assertSame(30, $profile->clockSkew());
    }

    public function test_it_refuses_a_timestamp_window_that_is_not_positive(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The timestamp TTL must be a positive number of seconds.');

        new SecurityProfile(timestampTtl: 0);
    }

    public function test_it_refuses_a_negative_clock_skew(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The clock skew must not be negative.');

        new SecurityProfile(clockSkew: -1);
    }

    public function test_a_zero_clock_skew_is_allowed(): void
    {
        static::assertSame(0, (new SecurityProfile(clockSkew: 0))->clockSkew());
    }

    public function test_it_composes_the_secure_default_crypto_policy(): void
    {
        $profile = SecurityProfile::default();

        static::assertSame(SignatureMethod::RSA_SHA256, $profile->crypto()->signatureMethod());
    }

    public function test_a_custom_crypto_policy_is_carried_through(): void
    {
        $profile = new SecurityProfile(crypto: new CryptoPolicy(signatureMethod: SignatureMethod::RSA_SHA512));

        static::assertSame(SignatureMethod::RSA_SHA512, $profile->crypto()->signatureMethod());
        // the window keeps its defaults
        static::assertSame(300, $profile->timestampTtl());
    }
}
