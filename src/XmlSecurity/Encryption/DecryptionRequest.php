<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalPartDecryption;

/**
 * The inputs to a single decryption operation: the container the xenc:EncryptedKey and xenc:ReferenceList are
 * read from (the caller locates it. The WS-Security profile passes the wsse:Security header addressed to it),
 * the recipient private key the OpenSSL\ module resolves internally, and the crypto policy whose allow-lists
 * govern which inbound algorithms are accepted.
 *
 * The container is required rather than defaulted to the document, because our public key is public: anyone can
 * wrap a session key to us, so an xenc:EncryptedKey found somewhere in the message is no evidence the sender
 * meant it for this recipient. Naming the container makes that judgement the caller's, where it belongs.
 *
 * A message may instead be encrypted under a key both sides already hold, and carry no xenc:EncryptedKey at
 * all. The session-key resolver is what reads such a message; the private key is what reads the wrapped kind.
 * A request supplying neither can decrypt nothing, which is a configuration to refuse rather than a state to
 * represent.
 */
final readonly class DecryptionRequest
{
    public CryptoPolicy $policy;

    /**
     * @throws InvalidArgumentException when neither a private key nor a session-key resolver is supplied
     */
    public function __construct(
        public Element $container,
        public ?Key $privateKey = null,
        ?CryptoPolicy $policy = null,
        public ?ExternalPartDecryption $externalParts = null,
        public ?SessionKeyResolver $sessionKeys = null,
    ) {
        if ($privateKey === null && $sessionKeys === null) {
            throw new InvalidArgumentException(
                'A decryption request needs either a recipient private key or a session-key resolver.',
            );
        }

        $this->policy = $policy ?? CryptoPolicy::default();
    }
}
