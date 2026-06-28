<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Formatter;

use Brick\Math\BigInteger;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

/**
 * Normalises a certificate serial number to a decimal integer string. openssl reports the serial in decimal
 * on some builds and hexadecimal on others; both are accepted, and serials larger than the platform integer
 * range are converted with arbitrary precision.
 */
final class SerialNumber
{
    /**
     * @param non-empty-string $serialNumber
     *
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the serial number is neither decimal nor hexadecimal
     */
    public function toDecimal(string $serialNumber): string
    {
        if (preg_match('/^\d+$/', $serialNumber) === 1) {
            return $serialNumber;
        }

        $hex = str_starts_with($serialNumber, '0x') ? substr($serialNumber, 2) : $serialNumber;
        if ($hex === '' || preg_match('/^[0-9A-Fa-f]+$/', $hex) !== 1) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        // Serial numbers routinely exceed the platform integer range, so the conversion keeps arbitrary precision.
        return (string) BigInteger::fromBase($hex, 16);
    }
}
