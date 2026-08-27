<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Dom\XPath;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\UniqueMatch;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves a reference under the WS-Security profile: wsu:Id, which the profile mandates for a signed or
 * encrypted part, and additionally the native Id a ds:Signature declares for itself.
 *
 * The second spelling is not a leniency. XML Signature declares `Id` of type ID on ds:Signature
 * (`resources/xsd/xmldsig-core-schema.xsd`), so a signature already has an id attribute of its own and a peer
 * covering one names it that way: WSS4J and CXF write `Id="SIG-..."` on the element and reference `#SIG-...`
 * from the endorsing signature. Resolving only wsu:Id leaves every endorsed message a peer sends unverifiable,
 * because the one reference that matters cannot be resolved at all.
 *
 * It stays narrow to that element on purpose. Accepting a bare `Id` anywhere would let an attacker name an
 * element of their own choosing by an attribute this profile never writes, which widens what a reference can
 * reach for no interop gain: nothing but a signature carries an id this package did not stamp itself.
 *
 * Both spellings are matched in one query, so the hardening is unchanged and covers them together: only these
 * two attributes, through an anchored XPath with the id embedded as a string literal, never getElementById or a
 * DTD-declared ID, and an id carried twice is refused as ambiguous rather than resolved to the first match.
 * Matching them separately would have let an id spelled both ways resolve, which is the ambiguity this refuses.
 */
final readonly class WsuIdLookup implements IdLookup
{
    /**
     * @param non-empty-string $id
     *
     * @throws IdReferenceException
     */
    public function lookup(Document $document, string $id): Element
    {
        $quoted = XPath::quote($id);

        return UniqueMatch::require(
            Query::elements(
                $document,
                '//*[@wsu:Id='.$quoted.'] | //ds:Signature[@Id='.$quoted.']',
                prefixes: [
                    'wsu' => WsseNamespaces::Wsu->value,
                    'ds' => Namespaces::Ds->value,
                ],
            )->map(static fn (Element $element): Element => $element),
            $id,
        );
    }
}
