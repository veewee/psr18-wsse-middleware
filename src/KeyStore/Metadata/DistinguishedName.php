<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore\Metadata;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

/**
 * An X.509 distinguished name in its RFC 2253 form: comma-separated Type=Value relative names with the
 * most-specific name first. Two names that differ only cosmetically across implementations (attribute-type
 * casing, surrounding whitespace, value casing) compare equal, so equals() can match a name rendered from a
 * parsed certificate against the same name carried as text in a key reference.
 */
final readonly class DistinguishedName
{
    /**
     * @param non-empty-string $value
     */
    private function __construct(
        private string $value,
        private string $comparable,
    ) {
    }

    /**
     * Renders a sequence of relative names as RFC 2253 text: the encoded order runs least-specific first, so
     * it is reversed, relative names are separated by commas, the values of one multi-valued relative name are
     * joined by a plus sign, and every value has the characters RFC 2253 reserves escaped.
     *
     * The input keeps each relative name distinct on purpose. A flat map of type to value cannot express the
     * difference between two relative names sharing a type and one relative name holding two values, and the
     * two are different distinguished names.
     *
     * @param list<non-empty-list<array{type: non-empty-string, value: string}>> $relativeNames
     *
     * @throws CryptoOperationFailed when the sequence renders empty
     */
    public static function fromRelativeNames(array $relativeNames): self
    {
        $rendered = [];
        foreach ($relativeNames as $relativeName) {
            $pairs = [];
            foreach ($relativeName as $pair) {
                $pairs[] = $pair['type'] . '=' . self::escapeValue($pair['value']);
            }

            $rendered[] = implode('+', array_reverse($pairs));
        }

        $name = implode(',', array_reverse($rendered));
        if ($name === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self($name, self::normalize($name));
    }

    /**
     * Wraps a distinguished name already in RFC 2253 text form, as carried in a ds:X509IssuerSerial reference.
     *
     * @throws CryptoOperationFailed when the name is empty
     */
    public static function fromString(string $name): self
    {
        $name = trim($name);
        if ($name === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self($name, self::normalize($name));
    }

    /**
     * @return non-empty-string
     */
    public function toString(): string
    {
        return $this->value;
    }

    public function equals(self $other): bool
    {
        return $this->comparable === $other->comparable;
    }

    /**
     * Folds a distinguished name to a comparison key: it is split into its relative components on unescaped
     * commas, each component split into attribute type and value on the first unescaped equals sign, the type
     * uppercased and the value whitespace-trimmed and case-folded. The component order is preserved, since
     * RFC 2253 orders relative names most-specific-first and that ordering is significant.
     */
    private static function normalize(string $name): string
    {
        $components = preg_split('/(?<!\\\\),/', $name);
        if ($components === false) {
            return $name;
        }

        $normalized = [];
        foreach ($components as $component) {
            // The values of one multi-valued relative name form a set, so their order carries no meaning and
            // two renderings that differ only in it name the same entity. Sorting them makes the key agree.
            $values = preg_split('/(?<!\\\\)\+/', $component);
            $pairs = array_map(self::normalizePair(...), $values === false ? [$component] : $values);
            sort($pairs);
            $normalized[] = implode('+', $pairs);
        }

        return implode(',', $normalized);
    }

    /**
     * Folds one attribute type and value: the type uppercased, the value whitespace-trimmed and case-folded.
     */
    private static function normalizePair(string $pair): string
    {
        $parts = preg_split('/(?<!\\\\)=/', $pair, 2);
        if ($parts === false || count($parts) !== 2) {
            return mb_strtolower(trim($pair));
        }

        return strtoupper(trim($parts[0])) . '=' . mb_strtolower(trim($parts[1]));
    }

    /**
     * Escapes the characters RFC 2253 reserves in an attribute value: the structural separators anywhere in
     * the value, a leading space or number sign, and a trailing space.
     */
    private static function escapeValue(string $value): string
    {
        $escaped = str_replace(
            ['\\', ',', '+', '"', '<', '>', ';'],
            ['\\\\', '\\,', '\\+', '\\"', '\\<', '\\>', '\\;'],
            $value,
        );

        if (str_starts_with($escaped, ' ') || str_starts_with($escaped, '#')) {
            $escaped = '\\' . $escaped;
        }

        if (str_ends_with($escaped, ' ')) {
            $escaped = substr($escaped, 0, -1) . '\\ ';
        }

        return $escaped;
    }
}
