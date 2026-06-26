<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Wsse;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
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
    /**
     * The canonical sequence, keyed by "{namespace}localName". Children not in this list keep their
     * relative order after the known ones.
     *
     * @var list<array{0: WsseNamespace, 1: string}>
     */
    private const SEQUENCE = [
        [WsseNamespace::Wsse, 'BinarySecurityToken'],
        [WsseNamespace::Wsu, 'Timestamp'],
        [WsseNamespace::Xenc, 'EncryptedKey'],
        [WsseNamespace::Xenc, 'ReferenceList'],
        [WsseNamespace::Ds, 'Signature'],
        [WsseNamespace::Xenc, 'EncryptedData'],
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
        foreach (self::SEQUENCE as $rank => [$namespace, $localName]) {
            if ($element->namespaceURI === $namespace->value && $element->localName === $localName) {
                return $rank;
            }
        }

        // Unknown elements sort after every known one.
        return count(self::SEQUENCE);
    }
}
