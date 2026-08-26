<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecureConversationVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use function VeeWee\Xml\Dom\Locator\Element\children;
use function VeeWee\Xml\Dom\Manipulator\append;

/**
 * Enforces the WS-Security element ordering inside wsse:Security. Receivers process the header top-down, so
 * EncryptedKey must precede the Signature that depends on the decrypted key, and a BinarySecurityToken must
 * precede any reference to it. A wrong order makes interop peers reject the message; sorting here lets token
 * builders append in any order and still produce a valid header.
 *
 * This ordering is the WS-Security header profile's, not XML-Security's, which is why it lives here. Plain
 * XML-DSig and XML-Enc impose no order at all -- a ds:Signature may sit wherever the document puts it -- so an
 * engine sorting its own output by this sequence would be applying a rule only this profile has. The blocks sort
 * the header once the engine has written into it.
 */
final class NodeOrder
{
    private const SAML11_ASSERTION = 'urn:oasis:names:tc:SAML:1.0:assertion';
    private const SAML20_ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    /**
     * The canonical sequence, by namespace URI + local name. Every security token (binary, username, SAML)
     * precedes the Signature that may reference it, and so does a SignatureConfirmation, which a response
     * signature may cover. Children not in this list keep their relative order after the known ones.
     *
     * Both WS-SecureConversation dialects are ranked, because a message carries whichever one its peer speaks.
     *
     * @var list<array{0: non-empty-string, 1: string}>
     */
    private const SEQUENCE = [
        [WsseNamespaces::Wsse->value, 'BinarySecurityToken'],
        [WsseNamespaces::Wsse->value, 'UsernameToken'],
        [WsseNamespaces::Wsu->value, 'Timestamp'],
        [self::SAML11_ASSERTION, 'Assertion'],
        [self::SAML20_ASSERTION, 'Assertion'],
        [Namespaces::Xenc->value, 'EncryptedKey'],
        // A derived key follows the token it derives from and precedes anything keyed by it.
        [WsSecureConversationVersion::V2005_02->value, 'DerivedKeyToken'],
        [WsSecureConversationVersion::V2005_12->value, 'DerivedKeyToken'],
        [Namespaces::Xenc->value, 'ReferenceList'],
        [WsseNamespaces::Wsse11->value, 'SignatureConfirmation'],
        [Namespaces::Ds->value, 'Signature'],
        [Namespaces::Xenc->value, 'EncryptedData'],
    ];

    public static function sort(Element $securityElement): void
    {
        // The sort is stable, so unknown children (and ties within one rank) keep their original
        // relative order without a tiebreaker.
        $sorted = children($securityElement)
            ->sort(static fn (Element $a, Element $b): int => self::rankOf($a) <=> self::rankOf($b))
            ->map(static fn (Element $child): Element => $child);

        // Re-appending an existing child moves it to the end, so appending in target order reorders
        // the element in place without detaching anything.
        append(...$sorted)($securityElement);
    }

    private static function rankOf(Element $element): int
    {
        foreach (self::SEQUENCE as $rank => [$namespaceUri, $localName]) {
            if (ElementName::matchesUri($element, $namespaceUri, $localName)) {
                return $rank;
            }
        }

        // Unknown elements sort after every known one.
        return count(self::SEQUENCE);
    }
}
