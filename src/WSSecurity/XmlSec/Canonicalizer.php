<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec;

use Dom\Node;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;

/**
 * Canonicalises a node for signing or digesting. Implementations MUST throw a canonicalization failure on
 * both an empty string and a false result (either is the CVE-2025-66578 class), so a silent empty C14N can
 * never be signed or compared.
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
