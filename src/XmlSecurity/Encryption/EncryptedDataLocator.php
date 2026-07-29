<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\UniqueMatch;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves an xenc:DataReference target to the single xenc:EncryptedData that carries it.
 *
 * An encrypted part may be tagged two ways: with the profile's id attribute (whatever the injected IdLookup
 * resolves — xml:id for a standalone caller, wsu:Id under WS-Security), or with the native, namespace-less
 * XML-Encryption Id attribute that some interop peers emit. Both are accepted, but the resolved element must be
 * an xenc:EncryptedData, so a stray id elsewhere cannot be targeted. Each path keeps the hardening: anchored
 * XPath, never getElementById or DTD-declared IDs, the id embedded as a string literal, and a duplicate carrier
 * rejected as ambiguous instead of silently resolving to the first match.
 */
final class EncryptedDataLocator
{
    public function __construct(
        private IdLookup $idLookup,
    ) {
    }

    /**
     * @param non-empty-string $id
     *
     * @throws IdReferenceException when no xenc:EncryptedData carries the id, or more than one does
     */
    public function resolve(Document $document, string $id): Element
    {
        $candidates = $this->nativeMatches($document, $id);

        try {
            $viaConvention = $this->idLookup->lookup($document, $id);
            if ($this->isEncryptedData($viaConvention) && !in_array($viaConvention, $candidates, true)) {
                $candidates[] = $viaConvention;
            }
        } catch (IdReferenceException $exception) {
            // An ambiguous convention id means several elements claim it: that is ambiguous regardless of the
            // native matches, so it must not be masked. A plain not-found only means the convention did not
            // carry the id; the native attribute checked above may still resolve it.
            if ($exception->ambiguous) {
                throw $exception;
            }
        }

        return UniqueMatch::require($candidates, $id);
    }

    /**
     * The xenc:EncryptedData elements carrying the id in the native, namespace-less XML-Encryption Id attribute.
     *
     * @param non-empty-string $id
     *
     * @return list<Element>
     */
    private function nativeMatches(Document $document, string $id): array
    {
        return Query::elements(
            $document,
            '//xenc:EncryptedData[@Id='.XPath::quote($id).']',
            prefixes: [Namespaces::Xenc->prefix() => Namespaces::Xenc->uri()],
        )
            ->map(static fn (Element $element): Element => $element);
    }

    private function isEncryptedData(Element $element): bool
    {
        return ElementName::matches($element, Namespaces::Xenc, 'EncryptedData');
    }
}
