<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

/**
 * How a dereferencing transform canonicalizes whatever it resolves to: the method, and the
 * inclusive-namespaces prefix list that goes with it.
 *
 * Read from the transform's own parameters without resolving anything, because the algorithm allow-list has to
 * pass judgement on the method before the verifier spends work resolving references. The pair travels as one
 * value rather than two positional slots, since a method applied without its prefix list produces different
 * bytes.
 *
 * @psalm-immutable
 */
final readonly class TransformCanonicalization
{
    /**
     * @param list<string> $inclusivePrefixes
     */
    public function __construct(
        public SignatureCanonicalization $canonicalization,
        public array $inclusivePrefixes,
    ) {
    }
}
