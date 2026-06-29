<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Metadata;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\SerialNumberParser;
use function Psl\Type\non_empty_string;

/**
 * A certificate serial number in decimal form, the value a ds:X509SerialNumber carries.
 */
final readonly class SerialNumber
{
    /**
     * @param non-empty-string $decimal
     */
    private function __construct(
        private string $decimal,
    ) {
    }

    /**
     * @throws CryptoOperationFailed when the value is not a decimal integer
     */
    public static function fromDecimal(string $decimal): self
    {
        if (preg_match('/^\d+$/', $decimal) !== 1) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self(non_empty_string()->coerce($decimal));
    }

    /**
     * Reads the serial number as openssl reports it (decimal or hexadecimal, of any size).
     *
     * @throws CryptoOperationFailed when the value is neither decimal nor hexadecimal
     */
    public static function fromRaw(string $serialNumber): self
    {
        return (new SerialNumberParser())->parse($serialNumber);
    }

    /**
     * @return non-empty-string
     */
    public function toString(): string
    {
        return $this->decimal;
    }
}
