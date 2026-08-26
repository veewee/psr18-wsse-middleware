<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Element;
use VeeWee\Xml\Dom\Document;

/**
 * Whether an element carries its own value or stands in for bytes travelling in a MIME part beside it.
 *
 * MTOM/XOP replaces an element's value with an xop:Include naming the part that holds it. The element is
 * still where the value belongs, so a caller asking "is this element's content really here" has to look for
 * the placeholder rather than at the element's text.
 *
 * The lookup is by namespace, never by local name or prefix: a message binds whatever prefix it likes, and an
 * element a peer happens to have called Include is not a placeholder.
 */
final class XopInclude
{
    private const string NAMESPACE_URI = 'http://www.w3.org/2004/08/xop/include';

    /**
     * Whether the element is an xop:Include, or holds one at any depth below it.
     *
     * Scoped to the element the caller named. An include belonging to a sibling says nothing about this
     * element's own content.
     */
    public static function presentIn(Document $document, Element $element): bool
    {
        return Query::elements(
            $document,
            './/xop:Include | self::xop:Include',
            $element,
            ['xop' => self::NAMESPACE_URI],
        )->count() > 0;
    }
}
