<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Exception;

use RuntimeException;

/**
 * Raised when a PKCS#12 blob cannot be loaded into a key store. The messages stay generic on purpose:
 * the passphrase and the raw OpenSSL error queue can leak key material, so they never reach the message.
 */
final class Pkcs12Exception extends RuntimeException
{
    public static function unreadable(): self
    {
        return new self('The PKCS#12 data could not be read; check the passphrase.');
    }

    public static function withoutCaChain(): self
    {
        return new self('The PKCS#12 data does not embed a CA chain to build a trust store from.');
    }
}
