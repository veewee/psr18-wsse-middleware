<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

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
     * @return list<Element>
     */
    public static function named(Element $parent, Namespaces $namespace, string $localName): array
    {
        return children($parent)
            ->filter(
                static fn (Element $child): bool => $child->localName === $localName
                    && $child->namespaceURI === $namespace->value,
            )
            ->map(static fn (Element $child): Element => $child);
    }
}
