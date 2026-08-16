<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use phpseclib3\File\X509;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateRevocationList;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\SerialNumber;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\DistinguishedNameParser;
use Throwable;
use function Psl\Type\array_key;
use function Psl\Type\dict;
use function Psl\Type\mixed;
use function Psl\Type\string;
use function Psl\Type\vec;

/**
 * Decides whether a certificate that already chains to an anchor has been revoked, against the revocation lists
 * the trust store carries. Nothing here reaches the network: the lists are integrator-supplied, so the check
 * adds no fetch, no timeout, and no denial-of-service lever to the inbound path.
 *
 * The rule is fail-closed in every direction. A signer is accepted only when a list that is trusted, current,
 * and issued by that signer's own issuer stays silent about its serial. Revoked rejects; no list covering the
 * issuer rejects, because revocation that skips the issuers you forgot to supply reads as enabled while
 * checking nothing; a list past its nextUpdate rejects, since a stalled refresh must not become a way to
 * disable the check; and a list whose signature does not verify against an anchor rejects, because an
 * unverified list is attacker-controlled input and a forged empty one would un-revoke everything.
 *
 * The parsing runs on phpseclib because PHP's openssl extension exposes no CRL API at all.
 */
final class RevocationCheck
{
    private readonly DistinguishedNameParser $names;

    public function __construct()
    {
        $this->names = new DistinguishedNameParser();
    }

    /**
     * @throws CertificateTrustException
     */
    public function assertNotRevoked(Certificate $leaf, TrustStore $trust, Timestamp $now): void
    {
        try {
            $issuerSerial = $leaf->info()->issuerSerial();
        } catch (Throwable) {
            throw CertificateTrustException::unreadable();
        }

        foreach ($this->currentListsCovering($issuerSerial->issuer, $trust, $now) as $covering) {
            $this->assertRevokesNot($covering, $issuerSerial->serialNumber);
        }
    }

    /**
     * Every list issued by the signer's own issuer that is trusted and current, not merely the first one found.
     * A list issued by anyone else is not a weaker answer, it is no answer: it says nothing about this issuer's
     * certificates.
     *
     * All of them are read rather than one being chosen, because a rollover legitimately leaves two lists inside
     * their nextUpdate at once: the superseded one predates the compromise and stays silent while the current one
     * names the serial. Picking either would let the order an integrator happens to pass them in decide whether a
     * revoked signer is accepted. A serial named by any current list is revoked.
     *
     * @return non-empty-list<X509>
     *
     * @throws CertificateTrustException
     */
    private function currentListsCovering(DistinguishedName $issuer, TrustStore $trust, Timestamp $now): array
    {
        $anchors = $trust->anchors();
        $current = [];
        $refusal = null;

        foreach ($trust->revocationLists() as $revocationList) {
            // One unusable entry must not end the search: a later entry may be the one that covers this issuer.
            // Nothing is loosened by continuing, because a signer no list covers is still refused below.
            try {
                $parsed = $this->parse($revocationList, $anchors);
                $covers = $this->issuerOf($parsed)->equals($issuer);
            } catch (CertificateTrustException $exception) {
                $refusal ??= $exception;

                continue;
            }

            if (!$covers) {
                continue;
            }

            // Trust is asserted only for a list that actually covers this issuer, so an unrelated untrusted list
            // in the store cannot fail a verification it has no bearing on.
            if ($parsed->validateSignature() !== true) {
                // A covering list that cannot be believed is the most specific reason available, so it outranks
                // any earlier unreadable entry when reporting.
                $refusal = CertificateTrustException::revocationListUntrusted();

                continue;
            }

            // A list outside its own validity is set aside rather than refused outright: an expired one left in
            // the store beside its replacement is ordinary operational housekeeping, and it is only when no
            // current list survives that the staleness becomes the refusal.
            try {
                $this->assertCurrent($parsed, $now);
            } catch (CertificateTrustException $exception) {
                $refusal ??= $exception;

                continue;
            }

            $current[] = $parsed;
        }

        if ($current === []) {
            throw $refusal ?? CertificateTrustException::revocationUnknown();
        }

        return $current;
    }

    /**
     * @param list<Certificate> $anchors
     *
     * @throws CertificateTrustException
     */
    private function parse(CertificateRevocationList $revocationList, array $anchors): X509
    {
        $reader = new X509();
        // One anchor per call: loadCA reads a single certificate, so handing it a concatenated bundle registers
        // whichever one comes first and silently discards the rest. Every list would then have to be issued by
        // that one anchor, and a two-partner store would refuse every message from the second partner.
        foreach ($anchors as $anchor) {
            $reader->loadCA($anchor->contents());
        }

        try {
            if ($reader->loadCRL($revocationList->contents()) === false) {
                throw CertificateTrustException::revocationListUnreadable();
            }
        } catch (CertificateTrustException $exception) {
            throw $exception;
        } catch (Throwable) {
            throw CertificateTrustException::revocationListUnreadable();
        }

        return $reader;
    }

    /**
     * @throws CertificateTrustException
     */
    private function issuerOf(X509 $revocationList): DistinguishedName
    {
        // Rendered from the encoded sequence by the same code that renders a certificate's issuer. phpseclib's
        // DN_STRING joins the sequence least-specific first while RFC 2253 is most-specific first, so taking that
        // shortcut here made every multi-attribute issuer compare unequal and rejected every signer.
        try {
            return $this->names->fromEncodedName($revocationList->getIssuerDN(X509::DN_ARRAY));
        } catch (Throwable) {
            throw CertificateTrustException::revocationListUnreadable();
        }
    }

    /**
     * A list is current between the instant it states it was issued and the one it states it expires. A list with
     * no nextUpdate states no expiry and so can never be shown to be current; it is refused rather than treated
     * as valid forever. A thisUpdate still in the future is equally not evidence about now: it is a list from a
     * misconfigured clock or a fabricated one, and reading it would let a future-dated empty list stand in for
     * the one currently naming a compromised serial.
     *
     * @throws CertificateTrustException
     */
    private function assertCurrent(X509 $revocationList, Timestamp $now): void
    {
        // phpseclib returns the parsed structure untyped, so the shape is coerced here rather than trusted.
        try {
            $parsed = dict(array_key(), mixed())->coerce($revocationList->getCurrentCert());
        } catch (Throwable) {
            throw CertificateTrustException::revocationListUnreadable();
        }

        $issuedAt = $this->statedTime($parsed, 'thisUpdate');
        if ($issuedAt !== null && $now->getSeconds() < $issuedAt) {
            throw CertificateTrustException::revocationListNotYetCurrent();
        }

        $expiresAt = $this->statedTime($parsed, 'nextUpdate');
        if ($expiresAt === null) {
            throw CertificateTrustException::revocationListStale();
        }

        if ($now->getSeconds() >= $expiresAt) {
            throw CertificateTrustException::revocationListStale();
        }
    }

    /**
     * @throws CertificateTrustException
     */
    private function assertRevokesNot(X509 $revocationList, SerialNumber $serialNumber): void
    {
        // listRevoked() reports serials in decimal, which is the form SerialNumber normalises to, so the
        // comparison needs no base guessing and holds for serials beyond the platform integer range.
        try {
            $revoked = vec(string())->coerce($revocationList->listRevoked());
        } catch (Throwable) {
            throw CertificateTrustException::revocationListUnreadable();
        }

        if (in_array($serialNumber->toString(), $revoked, true)) {
            throw CertificateTrustException::revoked();
        }
    }

    /**
     * One of the instants a CRL states, in whichever ASN.1 time form it used, as an epoch second: or null when
     * it states none. The decoded string carries its own UTC offset, so the epoch it resolves to does not depend
     * on the server's configured timezone.
     *
     * @param array<array-key, mixed> $parsed
     *
     * @throws CertificateTrustException when the field is present but cannot be read as an instant
     */
    private function statedTime(array $parsed, string $field): ?int
    {
        $tbs = $parsed['tbsCertList'] ?? null;
        if (!is_array($tbs)) {
            return null;
        }

        $stated = $tbs[$field] ?? null;
        if (!is_array($stated)) {
            return null;
        }

        foreach (['utcTime', 'generalTime'] as $form) {
            if (!isset($stated[$form]) || !is_string($stated[$form]) || $stated[$form] === '') {
                continue;
            }

            $instant = strtotime($stated[$form]);
            if ($instant === false) {
                throw CertificateTrustException::revocationListUnreadable();
            }

            return $instant;
        }

        return null;
    }
}
