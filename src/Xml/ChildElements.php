<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Element;
use function VeeWee\Xml\Dom\Locator\Element\children;

/**
 * Locates the direct child elements of a parent that match a local name in a specific namespace.
 *
 * It returns only direct children, never descendants, and matches on the full namespace URI so an
 * unqualified element can never stand in for a namespaced one. The count rule (exactly one, at most one)
 * and the exception thrown on a violation stay with each caller, so the security intent and the caller's
 * own failure type remain visible at the call site.
 */
final class ChildElements
{
    /**
     * The one matching direct child, or null when there is none or more than one. A duplicate is reported the
     * same as an absence so an injected sibling can never shadow the element a reader depends on; the caller
     * turns the null into its own uniform failure.
     */
    public static function single(Element $parent, XmlNamespace $namespace, string $localName): ?Element
    {
        $matches = self::named($parent, $namespace, $localName);

        return count($matches) === 1 ? $matches[0] : null;
    }

    /**
     * @return list<Element>
     */
    public static function named(Element $parent, XmlNamespace $namespace, string $localName): array
    {
        return children($parent)
            ->filter(static fn (Element $child): bool => ElementName::matches($child, $namespace, $localName))
            ->map(static fn (Element $child): Element => $child);
    }
}
