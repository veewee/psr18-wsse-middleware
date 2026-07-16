<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

/**
 * The inputs to a single decryption operation: the recipient private key the OpenSSL\ module resolves
 * internally, and the crypto policy whose allow-lists govern which inbound algorithms are accepted.
 */
final readonly class DecryptionRequest
{
    public CryptoPolicy $policy;

    public function __construct(
        public Key $privateKey,
        ?CryptoPolicy $policy = null,
    ) {
        $this->policy = $policy ?? CryptoPolicy::default();
    }
}
