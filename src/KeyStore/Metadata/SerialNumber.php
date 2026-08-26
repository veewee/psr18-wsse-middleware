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
     * Reads a serial number stated in hexadecimal, of any size.
     *
     * Preferred over fromRaw wherever the base is known: an all-digit value is otherwise ambiguous, and a hex
     * serial such as 12345678 read as decimal is a different number than 305419896.
     *
     * @throws CryptoOperationFailed when the value is not hexadecimal
     */
    public static function fromHex(string $hexadecimal): self
    {
        return (new SerialNumberParser())->parseHex($hexadecimal);
    }

    /**
     * Reads the serial number as openssl reports it, which is decimal on some builds and hexadecimal on
     * others. Prefer fromHex where the base is known; this guesses, and can only guess.
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
