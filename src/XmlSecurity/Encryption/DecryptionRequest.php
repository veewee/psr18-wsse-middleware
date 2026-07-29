<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

/**
 * The inputs to a single decryption operation: the container the xenc:EncryptedKey and xenc:ReferenceList are
 * read from (the caller locates it. The WS-Security profile passes the wsse:Security header addressed to it),
 * the recipient private key the OpenSSL\ module resolves internally, and the crypto policy whose allow-lists
 * govern which inbound algorithms are accepted.
 *
 * The container is required rather than defaulted to the document, because our public key is public: anyone can
 * wrap a session key to us, so an xenc:EncryptedKey found somewhere in the message is no evidence the sender
 * meant it for this recipient. Naming the container makes that judgement the caller's, where it belongs.
 */
final readonly class DecryptionRequest
{
    public CryptoPolicy $policy;

    public function __construct(
        public Element $container,
        public Key $privateKey,
        ?CryptoPolicy $policy = null,
    ) {
        $this->policy = $policy ?? CryptoPolicy::default();
    }
}
