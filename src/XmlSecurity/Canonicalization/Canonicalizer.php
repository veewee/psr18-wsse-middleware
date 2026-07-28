<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

/**
 * Canonicalises a node for signing or digesting. Implementations MUST throw a canonicalization failure on
 * both an empty string and a false result, so a silent empty canonicalization can never be signed or
 * compared.
 */
interface Canonicalizer
{
    /**
     * @param list<string>|null $inclusivePrefixes the exclusive-c14n InclusiveNamespaces PrefixList
     * @param Element|null      $withoutSubtree    a descendant to drop from the node-set, for the
     *                                             enveloped-signature transform. The node is filtered out of
     *                                             the canonicalization rather than removed from the document:
     *                                             detaching or cloning would lose the namespace declarations
     *                                             inherited from ancestors and change the canonical bytes.
     *
     * @return non-empty-string
     */
    public function canonicalize(
        Node $node,
        SignatureCanonicalization $method,
        ?array $inclusivePrefixes = null,
        ?Element $withoutSubtree = null,
    ): string;
}
