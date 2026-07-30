<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidCertificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\KeyUsage;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\ValidityWindow;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;

/**
 * The verifyTrust primitive: establish that a signing certificate is trusted. Trust is decided against a
 * caller-supplied TrustStore (configured anchors / pinned certs), never the certificate embedded in the
 * message. Chain building uses the platform's X509_verify_cert (via openssl_x509_checkpurpose), so CA
 * constraints, path length and validity are enforced by audited code rather than hand-rolled.
 */
final class CertificateTrust
{
    private Clock $clock;
    private readonly RevocationCheck $revocationCheck;

    public function __construct(Clock $clock = new SystemClock())
    {
        $this->clock = $clock;
        $this->revocationCheck = new RevocationCheck();
    }

    public function withClock(Clock $clock): self
    {
        $clone = clone $this;
        $clone->clock = $clock;

        return $clone;
    }

    public function verify(CertificateChain $chain, TrustStore $trust): TrustedSigner
    {
        if ($trust->isEmpty()) {
            throw CertificateTrustException::noTrustAnchors();
        }

        $leaf = $chain->leaf();

        try {
            $info = $leaf->info();
        } catch (CryptoOperationFailed) {
            throw CertificateTrustException::unreadable();
        }

        $this->assertWithinValidity($info->validity());
        $this->assertMaySign($info->keyUsage());

        // A store entry may be the peer's own certificate rather than an issuer. That is the only way to say
        // "this service" instead of "anything that CA issued", and it cannot go through chain building: a
        // CA-issued certificate does not terminate at a self-signed certificate inside the store, and PHP
        // exposes no way to ask OpenSSL to accept a partial chain. Every other check still applies, so a
        // pinned certificate that is expired or forbidden from signing is refused above.
        if (!$this->isPinned($leaf, $trust)) {
            $this->assertChainsToAnchor($chain, $trust);
        }

        // Revocation runs last, once the certificate is known to chain to an anchor: asking whether an untrusted
        // certificate is revoked is meaningless, and the revocation lists are verified against those same anchors.
        if ($trust->checksRevocation()) {
            $this->revocationCheck->assertNotRevoked($leaf, $trust, $this->clock->now());
        }

        return new TrustedSigner($info->subject(), $leaf);
    }

    /**
     * Whether the presented certificate is itself one of the store entries, compared as DER so a difference in
     * PEM line wrapping or surrounding text cannot decide trust. An entry that cannot be decoded is skipped
     * rather than aborting the search, matching how the rest of the store tolerates an unusable entry.
     */
    private function isPinned(Certificate $leaf, TrustStore $trust): bool
    {
        try {
            $presented = $leaf->toBase64Der();
        } catch (InvalidCertificate) {
            return false;
        }

        foreach ($trust->anchors() as $anchor) {
            try {
                if (hash_equals($anchor->toBase64Der(), $presented)) {
                    return true;
                }
            } catch (InvalidCertificate) {
                continue;
            }
        }

        return false;
    }

    private function assertWithinValidity(ValidityWindow $validity): void
    {
        if (!$validity->permits($this->clock->now())) {
            throw CertificateTrustException::expired();
        }
    }

    private function assertMaySign(?KeyUsage $keyUsage): void
    {
        // No keyUsage extension means signing is not forbidden; if present it must allow digital signatures.
        if ($keyUsage !== null && !$keyUsage->permitsSigning()) {
            throw CertificateTrustException::invalidKeyUsage();
        }
    }

    private function assertChainsToAnchor(CertificateChain $chain, TrustStore $trust): void
    {
        // openssl_x509_checkpurpose loads CA / intermediate certs from disk by path; the bundles materialise
        // themselves to temp files whose streams are held for this method (deleting on scope exit, throw included).
        $anchors = $trust->toPem()->toResource();
        $intermediatesPem = $chain->intermediatesPem();
        $untrusted = $intermediatesPem?->toResource();

        // A null path would make openssl fall back to the system CA store, bypassing the configured anchors;
        // refusing trust is the only safe outcome.
        $anchorsPath = $anchors->uri() ?? throw CertificateTrustException::notTrusted();

        // false / -1 are both "not trusted"; only an explicit true is a verified chain to an anchor.
        [$trusted] = OpenSslCall::capture(
            static fn () => openssl_x509_checkpurpose(
                $chain->leaf()->contents(),
                X509_PURPOSE_ANY,
                [$anchorsPath],
                $untrusted?->uri(),
            ),
        );

        if ($trusted !== true) {
            throw CertificateTrustException::notTrusted();
        }
    }
}
