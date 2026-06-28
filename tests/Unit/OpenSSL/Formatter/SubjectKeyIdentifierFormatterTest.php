<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Formatter;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Formatter\SubjectKeyIdentifierFormatter;

final class SubjectKeyIdentifierFormatterTest extends TestCase
{
    public function test_it_converts_colon_separated_hex_to_base64_bytes(): void
    {
        $formatted = (new SubjectKeyIdentifierFormatter())->format('12:AB:CD');

        static::assertSame(base64_encode("\x12\xAB\xCD"), $formatted);
    }

    public function test_it_strips_a_leading_keyid_marker(): void
    {
        $formatted = (new SubjectKeyIdentifierFormatter())->format('keyid:12:AB:CD');

        static::assertSame(base64_encode("\x12\xAB\xCD"), $formatted);
    }

    public function test_it_throws_when_the_value_is_absent(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        (new SubjectKeyIdentifierFormatter())->format(null);
    }
}
