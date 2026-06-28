<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath as XpathConfigurator;
use VeeWee\Xml\Dom\Collection\NodeList;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves an xenc:DataReference target to the single xenc:EncryptedData that carries it.
 *
 * Unlike the signature path, an encrypted part may be tagged with either the wsu:Id attribute (as the engine's
 * own encryptor mints) or the native, namespace-less XML-Encryption Id attribute (as some interop peers emit).
 * Both forms are accepted, but only on an xenc:EncryptedData element, so a stray @Id elsewhere cannot be
 * targeted. The lookup keeps the signature path's hardening: an anchored XPath, never getElementById or
 * DTD-declared IDs, the id embedded as a string literal so a crafted value cannot alter the query, and a
 * duplicate carrier rejected as ambiguous instead of silently resolving to the first match.
 */
final class EncryptedData
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
     * @return NodeList<Element>
     */
    private static function matching(Document $document, string $id): NodeList
    {
        $quoted = XPath::quote($id);

        return $document
            ->xpath(new XpathConfigurator($document))
            ->query('//xenc:EncryptedData[@wsu:Id='.$quoted.' or @Id='.$quoted.']')
            ->expectAllOfType(Element::class);
    }
}
