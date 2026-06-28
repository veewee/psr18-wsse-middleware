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

    public function test_it_normalizes_cosmetic_differences_for_comparison(): void
    {
        // Same name, rendered with different attribute-type casing and spacing on each side.
        $left = (new DistinguishedName())->normalize('cn=Test CA, o=PHPro , C=BE');
        $right = (new DistinguishedName())->normalize('CN=test ca,O=phpro,c=be');

        static::assertSame($left, $right);
    }

    public function test_it_preserves_relative_name_order_when_normalizing(): void
    {
        // The most-specific-first ordering is significant, so two names differing only in order stay different.
        $left = (new DistinguishedName())->normalize('CN=Leaf,O=PHPro');
        $right = (new DistinguishedName())->normalize('O=PHPro,CN=Leaf');

        static::assertNotSame($left, $right);
    }

    public function test_it_keeps_an_escaped_comma_inside_a_value_when_normalizing(): void
    {
        $normalized = (new DistinguishedName())->normalize('CN=Doe\\, John,O=PHPro');

        static::assertSame('CN=doe\\, john,O=phpro', $normalized);
    }
}
