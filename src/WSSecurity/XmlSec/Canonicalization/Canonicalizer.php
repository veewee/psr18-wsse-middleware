<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization;

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
     *
     * @return non-empty-string
     */
    public function canonicalize(Node $node, SignatureCanonicalization $method, ?array $inclusivePrefixes = null): string;
}
