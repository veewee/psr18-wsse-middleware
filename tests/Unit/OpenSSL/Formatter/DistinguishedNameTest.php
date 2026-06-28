<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL\Formatter;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Formatter\DistinguishedName;

final class DistinguishedNameTest extends TestCase
{
    public function test_it_reverses_openssl_order_to_most_specific_first(): void
    {
        // openssl reports least-specific first; RFC 2253 puts the most-specific RDN first.
        $rendered = (new DistinguishedName())->render([
            'C' => 'BE',
            'O' => 'PHPro',
            'CN' => 'Test CA',
        ]);

        static::assertSame('CN=Test CA,O=PHPro,C=BE', $rendered);
    }

    public function test_it_joins_a_multi_valued_relative_name_with_a_plus(): void
    {
        $rendered = (new DistinguishedName())->render([
            'CN' => 'Leaf',
            'OU' => ['Engineering', 'Security'],
        ]);

        static::assertSame('OU=Engineering+OU=Security,CN=Leaf', $rendered);
    }

    public function test_it_escapes_reserved_characters(): void
    {
        $rendered = (new DistinguishedName())->render([
            'CN' => 'Doe, John + Co; "X" <Y>\\Z',
        ]);

        static::assertSame('CN=Doe\\, John \\+ Co\\; \\"X\\" \\<Y\\>\\\\Z', $rendered);
    }

    public function test_it_escapes_a_leading_space(): void
    {
        $rendered = (new DistinguishedName())->render(['CN' => ' Leading']);

        static::assertSame('CN=\\ Leading', $rendered);
    }

    public function test_it_escapes_a_leading_number_sign(): void
    {
        $rendered = (new DistinguishedName())->render(['CN' => '#Hash']);

        static::assertSame('CN=\\#Hash', $rendered);
    }

    public function test_it_escapes_a_trailing_space(): void
    {
        $rendered = (new DistinguishedName())->render(['CN' => 'Trailing ']);

        static::assertSame('CN=Trailing\\ ', $rendered);
    }

    public function test_it_throws_when_the_name_is_empty(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        (new DistinguishedName())->render([]);
    }
}
