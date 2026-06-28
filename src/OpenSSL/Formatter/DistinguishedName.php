<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Formatter;

use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;

/**
 * Renders a distinguished name in RFC 2253 form from the structured name openssl reports: comma-separated
 * Type=Value relative names with the most-specific name first, which reverses the order openssl reports.
 * Multi-valued relative names are joined with a plus sign, and the characters RFC 2253 reserves are escaped.
 */
final class DistinguishedName
{
    /**
     * @param array<non-empty-string, non-empty-string|list<non-empty-string>> $name
     *
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the structured name renders empty
     */
    public function render(array $name): string
    {
        $relativeNames = [];
        foreach ($name as $type => $value) {
            $values = is_array($value) ? $value : [$value];
            $pairs = [];
            foreach ($values as $single) {
                $pairs[] = $type . '=' . $this->escapeValue($single);
            }

            $relativeNames[] = implode('+', $pairs);
        }

        $rendered = implode(',', array_reverse($relativeNames));
        if ($rendered === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return $rendered;
    }

    /**
     * Normalizes an RFC 2253 distinguished name for robust comparison across implementations that render the
     * same name with cosmetic differences. The name is split into its relative components on unescaped commas,
     * each component is split into attribute type and value on the first unescaped equals sign, the type is
     * uppercased and the value is whitespace-trimmed and case-folded. The component order is preserved, since
     * RFC 2253 orders relative names most-specific-first and that ordering is significant.
     *
     * This does not decode RFC 2253 hex-encoded values or reorder multi-valued relative names, so two names
     * that are equal only after such decoding are treated as different. The forms compared here are produced by
     * the same renderer on both sides, so those edge cases do not arise in practice.
     */
    public function normalize(string $name): string
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
    private function escapeValue(string $value): string
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
