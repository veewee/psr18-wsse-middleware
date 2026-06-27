<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;

/**
 * The inputs to a single decryption operation: the recipient private key, named by a KeyHandle the OpenSSL\
 * module resolves internally.
 */
final readonly class DecryptionRequest
{
    public function __construct(
        public KeyHandle $privateKey,
    ) {
    }
}
