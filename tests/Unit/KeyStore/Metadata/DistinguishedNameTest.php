<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

final class DistinguishedNameTest extends TestCase
{
    public function test_it_renders_the_structured_name_most_specific_first(): void
    {
        // openssl reports least-specific first; RFC 2253 puts the most-specific RDN first.
        $name = DistinguishedName::fromStructured([
            'C' => 'BE',
            'O' => 'PHPro',
            'CN' => 'Test CA',
        ]);

        static::assertSame('CN=Test CA,O=PHPro,C=BE', $name->toString());
    }

    public function test_it_joins_a_multi_valued_relative_name_with_a_plus(): void
    {
        $name = DistinguishedName::fromStructured([
            'CN' => 'Leaf',
            'OU' => ['Engineering', 'Security'],
        ]);

        static::assertSame('OU=Engineering+OU=Security,CN=Leaf', $name->toString());
    }

    public function test_it_escapes_reserved_characters(): void
    {
        $name = DistinguishedName::fromStructured([
            'CN' => 'Doe, John + Co; "X" <Y>\\Z',
        ]);

        static::assertSame('CN=Doe\\, John \\+ Co\\; \\"X\\" \\<Y\\>\\\\Z', $name->toString());
    }

    public function test_it_escapes_a_leading_space(): void
    {
        static::assertSame('CN=\\ Leading', DistinguishedName::fromStructured(['CN' => ' Leading'])->toString());
    }

    public function test_it_escapes_a_leading_number_sign(): void
    {
        static::assertSame('CN=\\#Hash', DistinguishedName::fromStructured(['CN' => '#Hash'])->toString());
    }

    public function test_it_escapes_a_trailing_space(): void
    {
        static::assertSame('CN=Trailing\\ ', DistinguishedName::fromStructured(['CN' => 'Trailing '])->toString());
    }

    public function test_it_throws_when_the_structured_name_is_empty(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        DistinguishedName::fromStructured([]);
    }

    public function test_it_compares_cosmetic_differences_as_equal(): void
    {
        // Same name, rendered with different attribute-type casing and spacing on each side.
        $left = DistinguishedName::fromString('cn=Test CA, o=PHPro , C=BE');
        $right = DistinguishedName::fromString('CN=test ca,O=phpro,c=be');

        static::assertTrue($left->equals($right));
    }

    public function test_it_compares_a_rendered_name_equal_to_an_equivalent_parsed_name(): void
    {
        // The cert side renders from the structured name; the wire side parses a string. They must match.
        $rendered = DistinguishedName::fromStructured(['C' => 'BE', 'O' => 'PHPro', 'CN' => 'Test CA']);
        $parsed = DistinguishedName::fromString('cn=test ca, o=phpro, c=be');

        static::assertTrue($rendered->equals($parsed));
    }

    public function test_it_treats_a_different_relative_name_order_as_not_equal(): void
    {
        // The most-specific-first ordering is significant.
        $left = DistinguishedName::fromString('CN=Leaf,O=PHPro');
        $right = DistinguishedName::fromString('O=PHPro,CN=Leaf');

        static::assertFalse($left->equals($right));
    }

    public function test_it_keeps_an_escaped_comma_inside_a_value_when_comparing(): void
    {
        $left = DistinguishedName::fromString('CN=Doe\\, John,O=PHPro');
        $right = DistinguishedName::fromString('cn=doe\\, john,o=phpro');

        static::assertTrue($left->equals($right));
    }

    public function test_it_throws_when_the_parsed_name_is_empty(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        DistinguishedName::fromString('');
    }
}
