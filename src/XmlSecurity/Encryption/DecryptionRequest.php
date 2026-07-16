<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;

/**
 * The inputs to a single decryption operation: the recipient private key the OpenSSL\ module resolves
 * internally, and the profile whose allow-lists govern which inbound algorithms are accepted.
 */
final readonly class DecryptionRequest
{
    public SecurityProfile $profile;

    public function __construct(
        public Key $privateKey,
        ?SecurityProfile $profile = null,
    ) {
        $this->profile = $profile ?? SecurityProfile::default();
    }
}
