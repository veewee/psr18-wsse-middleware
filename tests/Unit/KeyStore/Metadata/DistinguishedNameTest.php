<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\KeyStore\Metadata;

use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

final class DistinguishedNameTest extends TestCase
{
    public function test_it_renders_the_sequence_most_specific_first(): void
    {
        // The encoded sequence runs least-specific first; RFC 2253 puts the most-specific relative name first.
        $name = $this->dn(['C' => 'BE'], ['O' => 'PHPro'], ['CN' => 'Test CA']);

        static::assertSame('CN=Test CA,O=PHPro,C=BE', $name->toString());
    }

    public function test_repeated_types_in_separate_relative_names_are_comma_separated(): void
    {
        // Two relative names that share a type stay two relative names. A plus sign here would claim a single
        // multi-valued relative name, which RFC 2253 reads as a different distinguished name.
        $name = $this->dn(['CN' => 'Leaf'], ['OU' => 'Engineering'], ['OU' => 'Security']);

        static::assertSame('OU=Security,OU=Engineering,CN=Leaf', $name->toString());
    }

    public function test_one_multi_valued_relative_name_is_joined_with_a_plus(): void
    {
        $name = DistinguishedName::fromRelativeNames([
            [['type' => 'DC', 'value' => 'com']],
            [['type' => 'OU', 'value' => 'Eng'], ['type' => 'CN', 'value' => 'Leaf']],
        ]);

        static::assertSame('CN=Leaf+OU=Eng,DC=com', $name->toString());
    }

    public function test_the_order_within_a_multi_valued_relative_name_does_not_affect_equality(): void
    {
        // RFC 4514 makes the values of one relative name a set, so a peer may render them in either order.
        $left = DistinguishedName::fromString('CN=Leaf+OU=Eng,DC=com');
        $right = DistinguishedName::fromString('OU=Eng+CN=Leaf,DC=com');

        static::assertTrue($left->equals($right));
    }

    public function test_it_escapes_reserved_characters(): void
    {
        $name = $this->dn(['CN' => 'Doe, John + Co; "X" <Y>\\Z']);

        static::assertSame('CN=Doe\\, John \\+ Co\\; \\"X\\" \\<Y\\>\\\\Z', $name->toString());
    }

    public function test_it_escapes_a_leading_space(): void
    {
        static::assertSame('CN=\\ Leading', $this->dn(['CN' => ' Leading'])->toString());
    }

    public function test_it_escapes_a_leading_number_sign(): void
    {
        static::assertSame('CN=\\#Hash', $this->dn(['CN' => '#Hash'])->toString());
    }

    public function test_it_escapes_a_trailing_space(): void
    {
        static::assertSame('CN=Trailing\\ ', $this->dn(['CN' => 'Trailing '])->toString());
    }

    public function test_it_throws_when_the_sequence_is_empty(): void
    {
        $this->expectException(CryptoOperationFailed::class);
        DistinguishedName::fromRelativeNames([]);
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
        $rendered = $this->dn(['C' => 'BE'], ['O' => 'PHPro'], ['CN' => 'Test CA']);
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

    /**
     * Builds a name from one single-valued relative name per argument, in encoded (least-specific-first) order.
     *
     * @param non-empty-array<non-empty-string, string> ...$relativeNames
     */
    private function dn(array ...$relativeNames): DistinguishedName
    {
        $sequence = [];
        foreach ($relativeNames as $relativeName) {
            $pairs = [];
            foreach ($relativeName as $type => $value) {
                $pairs[] = ['type' => $type, 'value' => $value];
            }

            $sequence[] = $pairs;
        }

        return DistinguishedName::fromRelativeNames($sequence);
    }

    public function test_a_hex_escape_names_the_same_entity_as_a_backslash_escape(): void
    {
        // RFC 4514 allows either form for the same character, so a peer emitting the hex escape names the
        // same entity. Reading them as different signers presents as an unknown certificate, which looks
        // exactly like an attack while being an ordinary rendering difference.
        static::assertTrue(
            DistinguishedName::fromString('CN=Acme\\2C Inc.,O=Acme')
                ->equals(DistinguishedName::fromString('CN=Acme\\, Inc.,O=Acme')),
        );
    }

    public function test_a_value_ending_in_a_backslash_does_not_swallow_the_next_component(): void
    {
        // The escaped backslash is even, so the comma after it is a live separator. Looking behind a single
        // character reads it as escaped and folds two relative names into one, which is how two different
        // names could end up sharing a key.
        $twoComponents = DistinguishedName::fromString('CN=ends-with\\\\,O=Acme');
        $oneComponent = DistinguishedName::fromString('CN=ends-with\\\\\\,O=Acme');

        static::assertFalse($twoComponents->equals($oneComponent));
    }

    public function test_hex_and_backslash_escapes_of_a_separator_still_differ_from_a_real_separator(): void
    {
        // The fold unescapes, so it has to re-escape before building the key. Without the re-escape these two
        // collapse to the same key: one is a single relative name whose value contains a comma, the other is
        // two relative names split on one. That is identity confusion rather than the fail-closed mismatch
        // this class had before unescaping existed, so it is the case that has to stay pinned.
        static::assertFalse(
            DistinguishedName::fromString('CN=a\\2Cb')
                ->equals(DistinguishedName::fromString('CN=a,b')),
        );
        static::assertFalse(
            DistinguishedName::fromString('CN=a\\,b')
                ->equals(DistinguishedName::fromString('CN=a,b')),
        );
    }

    public function test_an_uppercase_hex_escape_folds_with_a_lowercase_one(): void
    {
        static::assertTrue(
            DistinguishedName::fromString('CN=Acme\\2C Inc.')
                ->equals(DistinguishedName::fromString('CN=Acme\\2c Inc.')),
        );
    }
}
