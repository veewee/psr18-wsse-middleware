<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Node;

/**
 * Reads an element's text content with surrounding whitespace removed, the single normalisation every
 * reader applies before it interprets a text node (an id, a base64 body, a timestamp). Each caller keeps
 * its own emptiness check and failure type, so the security intent stays visible at the call site.
 */
final class ElementText
{
    public static function trimmed(Node $node): string
    {
        return trim((string) $node->textContent);
    }
}
