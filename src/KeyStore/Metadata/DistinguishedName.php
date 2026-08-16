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
     * uppercased and the value unescaped, whitespace-trimmed and case-folded. The component order is
     * preserved, since RFC 2253 orders relative names most-specific-first and that ordering is significant.
     *
     * The value is re-escaped before it goes into the key. Folding the unescaped text straight in would make
     * two structurally different names collide: CN=a\,O=b is one component whose value contains a comma, and
     * CN=a,O=b is two components, yet both unescape to the same characters. Re-escaping keeps the structure
     * recoverable from the key, so the fold can never turn two names into one.
     */
    private static function normalize(string $name): string
    {
        $normalized = [];
        foreach (self::splitUnescaped($name, ',') as $component) {
            // The values of one multi-valued relative name form a set, so their order carries no meaning and
            // two renderings that differ only in it name the same entity. Sorting them makes the key agree.
            $pairs = array_map(self::normalizePair(...), self::splitUnescaped($component, '+'));
            sort($pairs);
            $normalized[] = implode('+', $pairs);
        }

        return implode(',', $normalized);
    }

    /**
     * Splits on a delimiter that is not escaped, counting the run of backslashes before it: an odd run escapes
     * the delimiter, an even run is escaped backslashes followed by a live one. A single-character lookbehind
     * gets the second case wrong, reading the delimiter in a value ending in a literal backslash as escaped
     * and collapsing two relative names into one.
     *
     * @return list<string>
     */
    private static function splitUnescaped(string $subject, string $delimiter): array
    {
        $parts = [];
        $current = '';
        $backslashes = 0;

        for ($i = 0, $length = strlen($subject); $i < $length; ++$i) {
            $character = $subject[$i];

            if ($character === $delimiter && $backslashes % 2 === 0) {
                $parts[] = $current;
                $current = '';
                $backslashes = 0;

                continue;
            }

            $backslashes = $character === '\\' ? $backslashes + 1 : 0;
            $current .= $character;
        }

        $parts[] = $current;

        return $parts;
    }

    /**
     * Undoes RFC 4514 value escaping: a backslash followed by two hex digits is that byte, and a backslash
     * followed by anything else is that character. Both forms are legal for the same character, so a peer
     * writing CN=Acme\2C Inc. and one writing CN=Acme\, Inc. name the same entity and have to fold together.
     *
     * The hex-encoded whole-value form (#0c0b...) is deliberately not decoded: its content is DER rather than
     * text, so reading it means parsing an ASN.1 string type inside a comparison that decides trust. A name in
     * that form still compares equal to an identical one and unequal to a textual rendering of the same name,
     * which fails closed as an unknown signer rather than confusing two identities.
     */
    private static function unescapeValue(string $value): string
    {
        $unescaped = '';

        for ($i = 0, $length = strlen($value); $i < $length; ++$i) {
            if ($value[$i] !== '\\' || $i + 1 >= $length) {
                $unescaped .= $value[$i];

                continue;
            }

            $next = substr($value, $i + 1, 2);
            if (strlen($next) === 2 && ctype_xdigit($next)) {
                $unescaped .= chr((int) hexdec($next));
                $i += 2;

                continue;
            }

            $unescaped .= $value[$i + 1];
            ++$i;
        }

        return $unescaped;
    }

    /**
     * Folds one attribute type and value: the type uppercased, the value unescaped, whitespace-trimmed,
     * case-folded, and escaped again so the key keeps its structure.
     */
    private static function normalizePair(string $pair): string
    {
        $parts = self::splitUnescaped($pair, '=');
        if (count($parts) < 2) {
            return self::escapeValue(mb_strtolower(trim(self::unescapeValue($pair))));
        }

        $type = array_shift($parts);
        $value = implode('=', $parts);

        return strtoupper(trim($type)).'='.self::escapeValue(mb_strtolower(trim(self::unescapeValue($value))));
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
