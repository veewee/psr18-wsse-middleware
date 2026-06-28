<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL;

use Phpro\ResourceStream\Factory\TmpStream;
use Phpro\ResourceStream\ResourceStream;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Internal\OpenSslCall;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustedSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;

/**
 * The verifyTrust primitive: establish that a signing certificate is trusted. Trust is decided against a
 * caller-supplied TrustStore (configured anchors / pinned certs), never the certificate embedded in the
 * message. Chain building uses the platform's X509_verify_cert (via openssl_x509_checkpurpose), so CA
 * constraints, path length and validity are enforced by audited code rather than hand-rolled.
 */
final class CertificateTrust
{
    private readonly CertificateFieldExtractor $fields;

    public function __construct()
    {
        $this->fields = new CertificateFieldExtractor();
    }

    public function verify(CertificateChain $chain, TrustStore $trust): TrustedSigner
    {
        if ($trust->isEmpty()) {
            throw CertificateTrustException::noTrustAnchors();
        }

        $leaf = $chain->leaf();

        try {
            $subjectName = $this->fields->subjectName($leaf);
            $validity = $this->fields->validityWindow($leaf);
            $keyUsage = $this->fields->keyUsage($leaf);
        } catch (CryptoOperationFailed) {
            throw CertificateTrustException::unreadable();
        }

        $this->assertWithinValidity($validity['from'], $validity['to']);
        $this->assertMaySign($keyUsage);
        $this->assertChainsToAnchor($chain, $trust);

        return new TrustedSigner($subjectName, $leaf);
    }

    private function assertWithinValidity(int $validFrom, int $validTo): void
    {
        $now = time();
        if ($now < $validFrom || $now > $validTo) {
            throw CertificateTrustException::expired();
        }
    }

    private function assertMaySign(?string $keyUsage): void
    {
        // No keyUsage extension means signing is not forbidden; if present it must allow digital signatures.
        if ($keyUsage !== null && !str_contains($keyUsage, 'Digital Signature')) {
            throw CertificateTrustException::invalidKeyUsage();
        }
    }

    private function assertChainsToAnchor(CertificateChain $chain, TrustStore $trust): void
    {
        $leaf = $chain->leaf()->contents();
        // openssl_x509_checkpurpose loads CA / intermediate certs from disk by path, so the in-memory PEMs
        // are materialised to temp files. The TmpStream resources delete their files when they go out of
        // scope at the end of this method (including on the throw below) - no manual cleanup needed.
        $anchors = $this->materialise($this->concatenate($trust->anchors()));
        $intermediates = array_slice($chain->all(), 1);
        $untrusted = $intermediates === [] ? null : $this->materialise($this->concatenate($intermediates));

        $anchorsPath = $anchors->uri();

        // false / -1 are both "not trusted"; only an explicit true is a verified chain to an anchor.
        [$trusted] = OpenSslCall::capture(
            static fn () => openssl_x509_checkpurpose(
                $leaf,
                X509_PURPOSE_ANY,
                $anchorsPath === null ? [] : [$anchorsPath],
                $untrusted?->uri(),
            ),
        );

        if ($trusted !== true) {
            throw CertificateTrustException::notTrusted();
        }
    }

    /**
     * @param list<Certificate> $certificates
     */
    private function concatenate(array $certificates): string
    {
        return implode("\n", array_map(static fn (Certificate $certificate): string => $certificate->contents(), $certificates));
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
