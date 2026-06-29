<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;

/**
 * The trust-establishment adapter: it delegates verifyTrust to OpenSSL\CertificateTrust, which is the only
 * boundary allowed to reason about certificate validity and chaining. The verifier owns no private key, so
 * this carries nothing beyond the delegation.
 */
final class Resolver implements KeyResolver
{
    public function __construct(
        private CertificateTrust $certificateTrust,
    ) {
    }

    /**
     * @throws CertificateTrustException
     */
    public function verifyTrust(CertificateChain $chain, TrustStore $trust): TrustedSigner
    {
        return $this->certificateTrust->verify($chain, $trust);
    }
}
