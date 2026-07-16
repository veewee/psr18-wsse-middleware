<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Random;

/**
 * Generates a fresh random session key of the correct length for the given data-encryption method, drawing
 * every byte from the OpenSSL\ CSPRNG. No IV is generated here: the Cipher class mints the IV itself at
 * encrypt time. Centralizing the key-length derivation guarantees the key handed to the Cipher always matches
 * the declared algorithm.
 */
final class SessionKeyFactory
{
    public function __construct(
        private readonly Random $random = new Random(),
    ) {
    }

    public function generate(DataEncryptionMethod $method): SessionKey
    {
        return SessionKey::fromBytes($this->random->bytes($this->keyLength($method)));
    }

    /**
     * @return positive-int
     */
    private function keyLength(DataEncryptionMethod $method): int
    {
        return match ($method) {
            DataEncryptionMethod::AES128_CBC,
            DataEncryptionMethod::AES128_GCM => 16,
            DataEncryptionMethod::AES192_CBC,
            DataEncryptionMethod::AES192_GCM,
            DataEncryptionMethod::TRIPLEDES_CBC => 24,
            DataEncryptionMethod::AES256_CBC,
            DataEncryptionMethod::AES256_GCM => 32,
        };
    }
}
