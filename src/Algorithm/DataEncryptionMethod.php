<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Algorithm;

/**
 * XML-Enc bulk data-encryption algorithms. All cases representable for parity; acceptance is governed by the
 * SecurityProfile allow-list. `isGcm()` lets the cipher layer enforce the GCM authentication-tag length.
 */
enum DataEncryptionMethod: string
{
    case TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
    case AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
    case AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
    case AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
    case AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
    case AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';
    case AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';

    public function isGcm(): bool
    {
        return match ($this) {
            self::AES128_GCM, self::AES192_GCM, self::AES256_GCM => true,
            self::TRIPLEDES_CBC, self::AES128_CBC, self::AES192_CBC, self::AES256_CBC => false,
        };
    }

    /**
     * The IV length per method: 96 bits for GCM, and the block size for CBC (where IV length == block size).
     *
     * @return positive-int
     */
    public function ivLength(): int
    {
        return match ($this) {
            self::TRIPLEDES_CBC => 8,
            self::AES128_CBC, self::AES192_CBC, self::AES256_CBC => 16,
            self::AES128_GCM, self::AES192_GCM, self::AES256_GCM => 12,
        };
    }

    /**
     * The authentication-tag length: 128 bits for GCM, zero for the unauthenticated CBC modes.
     *
     * @return non-negative-int
     */
    public function tagLength(): int
    {
        return $this->isGcm() ? 16 : 0;
    }

    public static function default(): self
    {
        return self::AES256_GCM;
    }
}
