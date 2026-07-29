<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Element;

/**
 * Tests whether an element carries a given qualified name: the local name plus the full namespace URI.
 *
 * Both halves are always compared, so an unqualified element — or one in a look-alike namespace — can never
 * stand in for the element a reader expects. Every qualified-name test in the codebase runs through here, so
 * the rule is stated once rather than restated per call site.
 */
final class ElementName
{
    public static function matches(Element $element, XmlNamespace $namespace, string $localName): bool
    {
        return self::matchesUri($element, $namespace->uri(), $localName);
    }

    /**
     * For the namespaces that are not Namespaces cases: a SAML version, a canonicalization URI, a caller-
     * supplied ordering key.
     */
    public static function matchesUri(Element $element, string $namespaceUri, string $localName): bool
    {
        return $element->localName === $localName
            && $element->namespaceURI === $namespaceUri;
    }
}
