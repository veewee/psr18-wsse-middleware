<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;

/**
 * The canonicalized digest for one ds:Reference: the element's id (without '#'), the base64-encoded
 * digest value, the DigestMethod URI, and any InclusiveNamespaces prefixes the canonicalization was
 * parameterized with. SignedInfoBuilder uses these fields to emit ds:Reference.
 *
 * The prefix list travels with the digest rather than being resolved again at emit time, so what the
 * reference declares is provably what its digest was computed under.
 */
final readonly class DigestResult
{
    /**
     * @param non-empty-string $id                the bare id value, without the '#' fragment prefix
     * @param non-empty-string $digestValueBase64 the base64 of the raw digest bytes, ready for ds:DigestValue
     * @param list<string>     $inclusivePrefixes the exclusive-c14n PrefixList the digest was computed under
     */
    public function __construct(
        public string $id,
        public string $digestValueBase64,
        public DigestMethod $digestMethod,
        public array $inclusivePrefixes = [],
    ) {
    }
}
