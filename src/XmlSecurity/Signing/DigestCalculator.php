<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use function Psl\Type\non_empty_string;

/**
 * Digests what a ds:Reference points at, and returns the reference the SignedInfoBuilder emits. The base64
 * of the raw digest is applied here, so the builder places the value verbatim.
 *
 * Two entry points, because there are two kinds of thing to digest and only one kind of answer.
 * forElement canonicalizes a node-set first, since XML has more than one byte representation of the same
 * tree. forExternalPart canonicalizes nothing: an attachment's octets are already the bytes both sides
 * agree on, and inventing a normalization step is how a digest stops matching.
 */
final class DigestCalculator
{
    public function __construct(
        private Canonicalizer $canonicalizer,
        private Digest $digest,
    ) {
    }

    /**
     * @param list<string> $inclusivePrefixes the exclusive-c14n PrefixList to canonicalize under, if any
     *
     * @throws CanonicalizationFailed when the element cannot be canonicalized (propagated from the canonicalizer)
     */
    public function forElement(
        ResolvedReference $reference,
        SignatureCanonicalization $method,
        DigestMethod $digestMethod,
        array $inclusivePrefixes = [],
    ): SignedReference {
        $canonical = $this->canonicalizer->canonicalize(
            $reference->element,
            $method,
            $inclusivePrefixes === [] ? null : $inclusivePrefixes,
        );

        // The raw digest crosses in from native hash() as a plain string, so its non-emptiness is coerced
        // rather than asserted: this is the boundary where it enters the typed contract the reference declares.
        $digest = non_empty_string()->coerce(base64_encode($this->digest->hash($canonical, $digestMethod)));

        // A PrefixList parameterizes exclusive C14N only: inclusive C14N already emits every declaration in
        // scope, so pinning one there would declare a constraint the digest was not computed under.
        $prefixes = $method->isExclusive() ? $inclusivePrefixes : [];

        return new SignedReference(
            '#'.$reference->id,
            $digest,
            $digestMethod,
            [new SignedTransform($method->value, $prefixes)],
        );
    }

    /**
     * Digests an external part's octets exactly as they travel: no canonicalization, no transfer-encoding
     * step, which is what the SwA content transform specifies and what makes the digest reproducible by a
     * peer that only sees the bytes.
     *
     * The URI is the part's reference verbatim, so a digest is bound to one specific part. Swapping two parts
     * is then a digest mismatch rather than a silent substitution.
     *
     * @param non-empty-string $transform
     */
    public function forExternalPart(
        ExternalPart $part,
        DigestMethod $digestMethod,
        string $transform,
    ): SignedReference {
        $digest = non_empty_string()->coerce(
            base64_encode($this->digest->hash($part->content->rewind()->getContents(), $digestMethod)),
        );

        return new SignedReference(
            $part->reference,
            $digest,
            $digestMethod,
            [new SignedTransform($transform)],
        );
    }
}
