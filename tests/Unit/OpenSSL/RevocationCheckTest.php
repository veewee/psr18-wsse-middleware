<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateRevocationList;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidTrustStore;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use SoapTest\Psr18WsseMiddleware\Unit\Clock\FrozenClock;

/**
 * Revocation is opt-in, and once opted in it is fail-closed: a signer is accepted only when a list that is
 * trusted, current, and issued by the signer's own issuer says nothing about it. Every other outcome — revoked,
 * no list covering that issuer, a list past its nextUpdate, or a list whose signature does not verify against an
 * anchor — rejects. Revocation that silently skips the issuers you forgot to supply is worse than none, because
 * the configuration reads as enabled.
 *
 * Every rejection here asserts the reason, not just the exception type. Every trust failure shares one exception
 * class, so a test that only asserted the class would pass whichever rule fired — and each of these scenarios can
 * fail for more than one reason at once. Asserting the message is what pins the rule under test; the uniform,
 * non-identifying fault a peer sees is produced further out, at the SecurityFault boundary.
 */
final class RevocationCheckTest extends TestCase
{
    /**
     * 2036-01-01. Past the short-lived list's nextUpdate (a day after generation) but far inside the leaf's
     * validity (2056), so staleness fires without the certificate-expiry check firing first.
     */
    private const AFTER_SHORT_LIST_EXPIRED = 2082758400;

    public function test_without_revocation_lists_a_revoked_leaf_still_verifies(): void
    {
        // The opt-in half: revocation is off by default, matching WSS4J's ENABLE_REVOCATION=false.
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_leaf_absent_from_a_current_list_is_accepted(): void
    {
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            $this->trustWith('crl-empty.pem'),
        );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_revoked_leaf_is_rejected(): void
    {
        $this->assertRejectedBecause(
            'listed as revoked',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                $this->trustWith('crl-revoked.pem'),
            ),
        );
    }

    public function test_a_list_from_another_issuer_does_not_cover_our_signer(): void
    {
        // Fail closed on missing: a list is supplied, but not one issued by the signer's issuer, so nothing
        // vouches for this certificate. The unrelated CA is also anchored here, so the list is genuinely
        // trusted — otherwise this would pass on the signature rule instead of the coverage rule.
        $this->assertRejectedBecause(
            'No supplied revocation list covers the issuer',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                TrustStore::fromCertificates($this->certificate('ca.crt'), $this->certificate('other-ca.crt'))
                    ->withRevocationLists($this->revocationList('crl-other-ca.pem')),
            ),
        );
    }

    public function test_a_list_past_its_next_update_is_rejected(): void
    {
        $this->assertRejectedBecause(
            'past its nextUpdate',
            fn (): mixed => (new CertificateTrust())
                ->withClock(new FrozenClock(Timestamp::fromParts(self::AFTER_SHORT_LIST_EXPIRED)))
                ->verify(
                    CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                    $this->trustWith('crl-short.pem'),
                ),
        );
    }

    public function test_the_staleness_rule_does_not_reject_a_still_current_list(): void
    {
        // The other half of the test above: at that same instant a long-dated list is still current, so the
        // rejection there was the list going out of date and not merely the clock having moved.
        $signer = (new CertificateTrust())
            ->withClock(new FrozenClock(Timestamp::fromParts(self::AFTER_SHORT_LIST_EXPIRED)))
            ->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                $this->trustWith('crl-empty.pem'),
            );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_list_not_signed_by_a_trust_anchor_is_rejected(): void
    {
        // The forged list carries the real CA's issuer name, so it passes the coverage check and is stopped only
        // by the signature check. An unverified list is attacker-controlled input: a forged empty one would
        // un-revoke everything, and a forged populated one could revoke an honest signer.
        $this->assertRejectedBecause(
            'not signed by a configured trust anchor',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                $this->trustWith('crl-impostor.pem'),
            ),
        );
    }

    public function test_enabling_revocation_with_no_lists_is_refused_at_configuration_time(): void
    {
        // A store that requires revocation but carries nothing to check against would reject every message.
        // Failing at configuration says so immediately instead of at the first response.
        $this->expectException(InvalidTrustStore::class);

        TrustStore::fromCertificates($this->certificate('ca.crt'))->withRevocationLists();
    }

    /**
     * @param callable(): mixed $attempt
     */
    private function assertRejectedBecause(string $reason, callable $attempt): void
    {
        try {
            $attempt();
        } catch (CertificateTrustException $exception) {
            static::assertStringContainsString($reason, $exception->getMessage());

            return;
        }

        static::fail('Expected a CertificateTrustException because '.$reason.'.');
    }

    private function trustWith(string $revocationList): TrustStore
    {
        return TrustStore::fromCertificates($this->certificate('ca.crt'))
            ->withRevocationLists($this->revocationList($revocationList));
    }

    private function certificate(string $file): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/revocation/'.$file);
    }

    private function revocationList(string $file): CertificateRevocationList
    {
        return CertificateRevocationList::fromFile(FIXTURE_DIR.'/certificates/revocation/'.$file);
    }
}
