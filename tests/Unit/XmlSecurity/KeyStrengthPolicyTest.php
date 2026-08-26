<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity;

use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\PublicKeyFamily;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\PublicKeyStrength;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\VerifySignature;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

/**
 * A chain can be perfectly valid and still be signed by a key nobody should trust: the algorithm allow-lists
 * say nothing about key size, and OpenSSL's path validation has no key-size policy of its own. The floor is
 * therefore stated by the crypto policy, and it is checked before any digest or signature work.
 */
#[RequiresPhp('>= 8.4.21')]
final class KeyStrengthPolicyTest extends TestCase
{
    public function test_a_key_family_that_cannot_be_classified_is_refused(): void
    {
        // The floor is the only check that stops a trusted-CA-issued but undersized signer, and it is stated
        // through ext-openssl while the signature itself is verified through phpseclib. The two have different
        // acceptance sets, so a key openssl cannot classify is not thereby a key nothing can verify with: an
        // RSASSA-PSS SubjectPublicKeyInfo is the obvious candidate, and phpseclib loads it as RSA. Waving that
        // family through would leave a 512-bit signer under a trusted CA with no floor applied at all.
        static::assertFalse(
            CryptoPolicy::default()->acceptsPublicKeyStrength(
                new PublicKeyStrength(PublicKeyFamily::Other, 4096),
            ),
            'an unclassifiable family has no floor to be measured against, so it cannot be known safe',
        );
    }

    public function test_a_signer_below_the_default_rsa_floor_is_refused(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeafWithRsaBits(512);
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
        );
    }

    /**
     * WS-Security predates the 2048-bit norm, so the default floor admits 1024-bit signers rather than refusing
     * every legacy service outright.
     */
    public function test_a_1024_bit_signer_is_accepted_by_default(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeafWithRsaBits(1024);
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))(
            new WsseContext($document, SoapVersion::Soap12, new SecurityProfile()),
        );

        static::assertStringContainsString('<soap:Body', $document->toXmlString());
    }

    public function test_a_deployment_can_raise_the_floor_above_a_legacy_signer(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeafWithRsaBits(1024);
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
        $profile = new SecurityProfile(crypto: new CryptoPolicy(minimumRsaKeyBits: 2048));

        $this->expectException(SecurityFault::class);
        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))(
            new WsseContext($document, SoapVersion::Soap12, $profile),
        );
    }

    public function test_a_deployment_can_lower_the_floor_to_reach_an_older_peer(): void
    {
        $fixture = WsseSignatureFixture::caSignedLeafWithRsaBits(512);
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);
        $profile = new SecurityProfile(crypto: new CryptoPolicy(minimumRsaKeyBits: 512));

        (new VerifySignature(TrustStore::fromCertificates($fixture->caCertificate)))(
            new WsseContext($document, SoapVersion::Soap12, $profile),
        );

        static::assertStringContainsString('<soap:Body', $document->toXmlString());
    }

    public function test_an_elliptic_curve_signer_is_measured_against_the_ec_floor(): void
    {
        $fixture = WsseSignatureFixture::ecCaSignedLeaf();

        static::assertTrue((new CryptoPolicy())->acceptsEcKeyBits(256));
        static::assertFalse((new CryptoPolicy())->acceptsEcKeyBits(192));
        static::assertNotNull($fixture->leafCertificate->info()->publicKeyStrength());
    }
}
