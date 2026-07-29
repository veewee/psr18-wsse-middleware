<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Verification;

use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseKeyInfoResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\TrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureValidator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\WsseSignatureFixture;
use Throwable;

/**
 * Revocation adds five new ways for trust to fail, and a peer must not be able to tell any of them apart: from
 * each other, or from a plainly untrusted certificate. "Revoked" would leak that the signer was once legitimate;
 * "no list covers this issuer" and "the list is stale" would leak the state of the verifier's own configuration,
 * telling an attacker when the revocation check is effectively switched off.
 *
 * The fixture signs a real document to produce something the verifier will parse, which canonicalizes: hence
 * the version gate, for the libxml canonicalization defect and nothing else.
 */
#[RequiresPhp('>= 8.4.21')]
final class RevocationFaultUniformityTest extends TestCase
{
    /**
     * @return iterable<string, CertificateTrustException>
     */
    public static function trustFailures(): iterable
    {
        yield 'revoked' => CertificateTrustException::revoked();
        yield 'no list covers the issuer' => CertificateTrustException::revocationUnknown();
        yield 'the list is stale' => CertificateTrustException::revocationListStale();
        yield 'the list is not signed by an anchor' => CertificateTrustException::revocationListUntrusted();
        yield 'the list is unreadable' => CertificateTrustException::revocationListUnreadable();
        yield 'the certificate is simply untrusted' => CertificateTrustException::notTrusted();
    }

    public function test_every_revocation_failure_is_indistinguishable_from_plain_untrust(): void
    {
        $messages = [];
        $codes = [];

        foreach (self::trustFailures() as $origin => $cause) {
            $failure = $this->failureFrom($cause);

            static::assertInstanceOf(SignatureVerificationFailed::class, $failure, $origin);

            $messages[$origin] = $failure->getMessage();
            $codes[$origin] = $failure->getCode();

            // The operator-facing reason must not survive into what a peer can observe.
            $seen = strtolower($failure->getMessage());
            static::assertStringNotContainsString('revok', $seen, $origin);
            static::assertStringNotContainsString('nextupdate', $seen, $origin);
        }

        static::assertCount(1, array_unique($messages), 'every trust failure must share one message');
        static::assertCount(1, array_unique($codes), 'every trust failure must share one code');
    }

    public function test_the_underlying_reason_stays_available_for_operator_logs(): void
    {
        // Uniform to a peer, diagnosable locally. If the distinct reason vanished entirely, an operator could not
        // tell a genuinely revoked signer from a revocation list they forgot to refresh.
        static::assertStringContainsString('revoked', CertificateTrustException::revoked()->getMessage());
        static::assertStringContainsString(
            'nextUpdate',
            CertificateTrustException::revocationListStale()->getMessage(),
        );
    }

    private function failureFrom(CertificateTrustException $cause): Throwable
    {
        $fixture = WsseSignatureFixture::caSignedLeaf();
        $document = $fixture->sign([WsseSignatureFixture::bodyTarget()]);

        $canonicalizer = new DomCanonicalizer();
        $verifier = new Verifier(
            new SignatureLocator(),
            new SignedInfoParser(),
            new AlgorithmPolicyEnforcer(),
            new CertificateExtractor(new WsseKeyInfoResolver(), (new WsuIdConvention())->lookup()),
            new ReferenceResolver((new WsuIdConvention())->lookup()),
            new DigestVerifier($canonicalizer, new Digest()),
            new SignatureValidator($canonicalizer, new OpenSslSigner()),
            new ThrowingTrustResolver($cause),
        );

        try {
            $verifier->verify(
                $document,
                new VerificationPolicy(TrustStore::fromCertificates($fixture->caCertificate), CryptoPolicy::default()),
                $fixture->security($document),
            );
        } catch (Throwable $failure) {
            return $failure;
        }

        static::fail('Expected the verification to fail.');
    }
}

/**
 * A trust resolver that always refuses, with the exact cause under test.
 */
final class ThrowingTrustResolver implements TrustResolver
{
    public function __construct(
        private readonly CertificateTrustException $cause,
    ) {
    }

    public function verifyTrust(CertificateChain $chain, TrustStore $trust): TrustedSigner
    {
        throw $this->cause;
    }
}
