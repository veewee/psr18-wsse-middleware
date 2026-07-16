<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml\Manipulator;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use function VeeWee\Xml\Dom\Locator\Element\children;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Enforces the WS-Security element ordering inside wsse:Security. Receivers process the header
 * top-down, so EncryptedKey must precede the Signature that depends on the decrypted key, and a
 * BinarySecurityToken must precede any reference to it. A wrong order makes interop peers reject the
 * message; sorting here lets token builders append in any order and still produce a valid header.
 */
final class NodeOrder
{
    private const SAML11_ASSERTION = 'urn:oasis:names:tc:SAML:1.0:assertion';
    private const SAML20_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * The canonical sequence, by namespace URI + local name. A SAML assertion is a security token, so it
     * precedes the Signature that may reference it. Children not in this list keep their relative order
     * after the known ones.
     *
     * @var list<array{0: non-empty-string, 1: string}>
     */
    private const SEQUENCE = [
        [Namespaces::Wsse->value, 'BinarySecurityToken'],
        [Namespaces::Wsu->value, 'Timestamp'],
        [self::SAML11_ASSERTION, 'Assertion'],
        [self::SAML20_ASSERTION, 'Assertion'],
        [Namespaces::Xenc->value, 'EncryptedKey'],
        [Namespaces::Xenc->value, 'ReferenceList'],
        [Namespaces::Ds->value, 'Signature'],
        [Namespaces::Xenc->value, 'EncryptedData'],
    ];

    public static function sort(Element $securityElement): void
    {
        $ranked = [];
        foreach (children($securityElement) as $index => $child) {
            // Pair each child with (canonical rank, original index) so a stable sort keeps unknown
            // children, and ties within the same rank, in their original relative order.
            $ranked[] = [self::rankOf($child), $index, $child];
        }

        usort(
            $ranked,
            static fn (array $a, array $b): int => [$a[0], $a[1]] <=> [$b[0], $b[1]],
        );

        // Re-appending an existing child moves it to the end, so appending in target order reorders
        // the element in place without detaching anything.
        append(...array_map(static fn (array $entry): Element => $entry[2], $ranked))($securityElement);
    }

    private static function rankOf(Element $element): int
    {
        foreach (self::SEQUENCE as $rank => [$namespaceUri, $localName]) {
            if ($element->namespaceURI === $namespaceUri && $element->localName === $localName) {
                return $rank;
            }
        }

        // Unknown elements sort after every known one.
        return count(self::SEQUENCE);
    }
}
