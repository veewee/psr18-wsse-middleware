<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use function Psl\Type\non_empty_string;

/**
 * Canonicalizes one resolved element, then digests the canonical bytes. Returns a DigestResult the
 * SignedInfoBuilder can emit as ds:Reference. The base64 of the raw digest is applied here, so the builder
 * places the value verbatim.
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
    public function calculate(
        ResolvedReference $reference,
        SignatureCanonicalization $method,
        DigestMethod $digestMethod,
        array $inclusivePrefixes = [],
    ): DigestResult {
        $canonical = $this->canonicalizer->canonicalize(
            $reference->element,
            $method,
            $inclusivePrefixes === [] ? null : $inclusivePrefixes,
        );

        // The raw digest crosses in from native hash() as a plain string, so its non-emptiness is coerced
        // rather than asserted: this is the boundary where it enters the typed contract DigestResult declares.
        $digest = non_empty_string()->coerce(base64_encode($this->digest->hash($canonical, $digestMethod)));

        // The list travels on the result so the reference declares exactly what it was digested under.
        return new DigestResult($reference->id, $digest, $digestMethod, $inclusivePrefixes);
    }
}
