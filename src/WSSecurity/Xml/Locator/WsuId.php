<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Query;
use VeeWee\Xml\Dom\Collection\NodeList;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves a `wsu:Id` reference (such as a DSig `URI="#..."`) to the single element that carries it.
 *
 * The lookup is hardened against signature-wrapping (XSW). It matches only the `wsu:Id` attribute through an
 * anchored XPath, never `getElementById` or DTD-declared IDs. The id is embedded as an XPath string literal,
 * so a crafted value cannot alter the query. A duplicate `wsu:Id` is rejected as ambiguous instead of
 * silently resolving to the first match.
 */
final class WsuId
{
    public static function resolve(Document $document, string $id): Element
    {
        $elements = self::matching($document, $id);

        return match ($elements->count()) {
            0 => throw IdReferenceException::notFound($id),
            1 => $elements->expectSingle(),
            default => throw IdReferenceException::ambiguous($id),
        };
    }

    /**
     * Whether no element yet carries this wsu:Id. A duplicate (more than one carrier) counts as taken, not
     * free, so a minter never adds to an existing ambiguity.
     */
    public static function isFree(Document $document, string $id): bool
    {
        return self::matching($document, $id)->count() === 0;
    }

    /**
     * @return NodeList<Element>
     */
    private static function matching(Document $document, string $id): NodeList
    {
        return Query::elements($document, '//*[@wsu:Id='.XPath::quote($id).']');
    }
}
