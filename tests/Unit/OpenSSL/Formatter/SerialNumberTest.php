<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Formatter;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Formatter\SerialNumber;

final class SerialNumberTest extends TestCase
{
    public function test_it_passes_a_decimal_serial_through_unchanged(): void
    {
        static::assertSame('1234567890', (new SerialNumber())->toDecimal('1234567890'));
    }

    public function test_it_converts_a_hex_serial_to_decimal(): void
    {
        static::assertSame('255', (new SerialNumber())->toDecimal('FF'));
    }

    public function test_it_converts_a_prefixed_hex_serial_to_decimal(): void
    {
        static::assertSame('255', (new SerialNumber())->toDecimal('0xFF'));
    }

    public function test_it_converts_a_serial_beyond_the_php_integer_range(): void
    {
        // A serial beyond the platform integer range must convert without precision loss.
        static::assertSame(
            '8954687866956160512684242411956916674',
            (new SerialNumber())->toDecimal('6BC9C32D3C1F62E0F44B6A6E8F2D1C2'),
        );
    }

    public function test_it_throws_on_a_malformed_serial(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        (new SerialNumber())->toDecimal('not-a-serial');
    }
}
