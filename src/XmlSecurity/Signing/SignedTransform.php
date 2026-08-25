<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

/**
 * One entry in a ds:Reference transform chain: the algorithm to declare, plus the ec:InclusiveNamespaces
 * prefix list if that algorithm is parameterized by one.
 *
 * The algorithm is a plain string rather than a SignatureCanonicalization, because not every transform is a
 * canonicalization. The SwA content transform selects an attachment's octets and canonicalizes nothing, and a
 * reference declaring it is still a perfectly ordinary ds:Reference.
 *
 * The prefix list travels with the transform rather than being resolved again at emit time, so what a
 * reference declares is provably what its digest was computed under.
 */
final readonly class SignedTransform
{
    /**
     * @param non-empty-string $algorithm
     * @param list<string>     $inclusivePrefixes only an exclusive canonicalization is parameterized by one
     */
    public function __construct(
        public string $algorithm,
        public array $inclusivePrefixes = [],
    ) {
    }
}
