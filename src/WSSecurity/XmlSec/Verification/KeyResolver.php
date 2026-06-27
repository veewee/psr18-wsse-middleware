<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Soap\Psr18WsseMiddleware\WSSecurity\Trust\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustedSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;

/**
 * Establishes that a signing certificate chain is trusted, against a caller-supplied TrustStore (configured
 * anchors / pinned certs), never the certificate embedded in the message.
 *
 * Trust only: there are no privateKey()/certificate() accessors. The raw OpenSSL key handle never leaves the
 * OpenSSL\ module. Signing and encryption pass a KeyHandle down so OpenSSL\ resolves and uses it internally.
 */
interface KeyResolver
{
    /**
     * @throws \Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException when the chain is not trusted
     */
    public function verifyTrust(CertificateChain $chain, TrustStore $trust): TrustedSigner;
}
