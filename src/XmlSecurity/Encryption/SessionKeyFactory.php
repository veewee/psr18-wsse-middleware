<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Random;

/**
 * Generates a fresh random session key of the requested length, drawing every byte from the OpenSSL\ CSPRNG.
 * No IV is generated here: the Cipher class mints the IV itself at encrypt time.
 *
 * The length is the caller's to state, because the algorithm that will consume the key is what defines it.
 * DataEncryptionMethod::keyLength() and SignatureMethod::hmacKeyLength() are where those lengths live.
 */
final class SessionKeyFactory
{
    public function __construct(
        private readonly Random $random = new Random(),
    ) {
    }

    /**
     * @param positive-int $bytes
     */
    public function generate(int $bytes): SessionKey
    {
        return SessionKey::fromBytes($this->random->bytes($bytes));
    }
}
