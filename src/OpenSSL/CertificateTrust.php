<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Phpro\ResourceStream\Factory\TmpStream;
use Phpro\ResourceStream\ResourceStream;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\KeyUsage;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\ValidityWindow;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\TrustStore;

/**
 * The verifyTrust primitive: establish that a signing certificate is trusted. Trust is decided against a
 * caller-supplied TrustStore (configured anchors / pinned certs), never the certificate embedded in the
 * message. Chain building uses the platform's X509_verify_cert (via openssl_x509_checkpurpose), so CA
 * constraints, path length and validity are enforced by audited code rather than hand-rolled.
 */
final class CertificateTrust
{
    public function verify(CertificateChain $chain, TrustStore $trust): TrustedSigner
    {
        if ($trust->isEmpty()) {
            throw CertificateTrustException::noTrustAnchors();
        }

        $leaf = $chain->leaf();

        // Only reading the fields can fail (the certificate is parsed lazily on first access); the accessors
        // below are plain getters over the parsed value.
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
        if (!$validity->permits(Timestamp::now())) {
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
        // openssl_x509_checkpurpose loads CA / intermediate certs from disk by path, so the in-memory PEMs
        // are materialised to temp files. The TmpStream resources delete their files when they go out of
        // scope at the end of this method (including on the throw below) - no manual cleanup needed.
        $anchors = $this->materialise($trust->toPem());
        $intermediatesPem = $chain->intermediatesPem();
        $untrusted = $intermediatesPem === null ? null : $this->materialise($intermediatesPem);

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

    /**
     * @return ResourceStream<resource>
     */
    private function materialise(string $contents): ResourceStream
    {
        $stream = TmpStream::create();
        $stream->write($contents);
        // Flush: openssl_x509_checkpurpose opens the path with a separate descriptor and would otherwise
        // read an empty file. unwrap() returns the live resource (it throws if the stream is closed).
        fflush($stream->unwrap());

        return $stream;
    }
}
