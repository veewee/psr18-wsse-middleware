<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves a `wsu:Id` reference (such as a DSig `URI="#..."`) to the single element that carries it.
 *
 * The lookup is hardened against signature-wrapping (XSW). It matches only the `wsu:Id` attribute through an
 * anchored XPath, never `getElementById` or DTD-declared IDs. The id is embedded as an XPath string literal,
 * so a crafted value cannot alter the query. A duplicate `wsu:Id` is rejected as ambiguous instead of
 * silently resolving to the first match.
 */
final class WsuIdResolver
{
    public static function resolve(Document $document, string $id): Element
    {
        $elements = $document
            ->xpath(new WsseXpath($document))
            ->query('//*[@wsu:Id='.XPath::quote($id).']')
            ->expectAllOfType(Element::class);

        return match ($elements->count()) {
            0 => throw IdReferenceException::notFound($id),
            1 => $elements->expectSingle(),
            default => throw IdReferenceException::ambiguous($id),
        };
    }
}
