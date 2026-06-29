<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Metadata;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

/**
 * An X.509 distinguished name in its RFC 2253 form: comma-separated Type=Value relative names with the
 * most-specific name first. Two names that differ only cosmetically across implementations (attribute-type
 * casing, surrounding whitespace, value casing) compare equal, so equals() can match a name rendered from a
 * parsed certificate against the same name carried as text in a key reference.
 */
final readonly class DistinguishedName
{
    private function __construct(
        private string $value,
        private string $comparable,
    ) {
    }

    /**
     * Renders the structured name openssl reports, reversing its least-specific-first order. Multi-valued
     * relative names are joined with a plus sign and the characters RFC 2253 reserves are escaped.
     *
     * @param array<non-empty-string, non-empty-string|list<non-empty-string>> $name
     *
     * @throws CryptoOperationFailed when the structured name renders empty
     */
    public static function fromStructured(array $name): self
    {
        $relativeNames = [];
        foreach ($name as $type => $value) {
            $values = is_array($value) ? $value : [$value];
            $pairs = [];
            foreach ($values as $single) {
                $pairs[] = $type . '=' . self::escapeValue($single);
            }

            $relativeNames[] = implode('+', $pairs);
        }

        $rendered = implode(',', array_reverse($relativeNames));
        if ($rendered === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self($rendered, self::normalize($rendered));
    }

    /**
     * Wraps a distinguished name already in RFC 2253 text form, as carried in a ds:X509IssuerSerial reference.
     *
     * @throws CryptoOperationFailed when the name is empty
     */
    public static function fromString(string $name): self
    {
        if (trim($name) === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return new self($name, self::normalize($name));
    }

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
            $parts = preg_split('/(?<!\\\\)=/', $component, 2);
            if ($parts === false || count($parts) !== 2) {
                $normalized[] = mb_strtolower(trim($component));
                continue;
            }

            $type = strtoupper(trim($parts[0]));
            $value = mb_strtolower(trim($parts[1]));
            $normalized[] = $type . '=' . $value;
        }

        return implode(',', $normalized);
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
