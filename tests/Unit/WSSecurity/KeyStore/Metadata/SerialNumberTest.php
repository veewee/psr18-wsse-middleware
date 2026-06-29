<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata\SerialNumber;

final class SerialNumberTest extends TestCase
{
    public function test_it_holds_a_decimal_serial(): void
    {
        static::assertSame('4242', SerialNumber::fromDecimal('4242')->toString());
    }

    public function test_it_throws_on_a_non_decimal_value(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        SerialNumber::fromDecimal('12AB');
    }

    public function test_it_throws_on_an_empty_value(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        SerialNumber::fromDecimal('');
    }

    public function test_it_parses_a_decimal_raw_serial(): void
    {
        static::assertSame('1234567890', SerialNumber::fromRaw('1234567890')->toString());
    }

    public function test_it_parses_a_hex_raw_serial(): void
    {
        static::assertSame('255', SerialNumber::fromRaw('FF')->toString());
    }

    public function test_it_parses_a_prefixed_hex_raw_serial(): void
    {
        static::assertSame('255', SerialNumber::fromRaw('0xFF')->toString());
    }

    public function test_it_parses_a_raw_serial_beyond_the_php_integer_range(): void
    {
        static::assertSame(
            '8954687866956160512684242411956916674',
            SerialNumber::fromRaw('6BC9C32D3C1F62E0F44B6A6E8F2D1C2')->toString(),
        );
    }

    public function test_it_throws_on_a_malformed_raw_serial(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        SerialNumber::fromRaw('not-a-serial');
    }
}
