<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Soap\Psr18WsseMiddleware\Clock\Clock;
use Soap\Psr18WsseMiddleware\Clock\SystemClock;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
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
    public function __construct(
        private readonly Clock $clock = new SystemClock(),
    ) {
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
        $this->assertChainsToAnchor($chain, $trust);

        return new TrustedSigner($info->subject(), $leaf);
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
