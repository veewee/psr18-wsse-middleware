<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

/**
 * The data read from one ds:Reference: the declared DigestMethod, the expected base64 digest value exactly as
 * it appears in ds:DigestValue, and the canonicalization this reference's digest is computed under together
 * with the inclusive-namespaces prefix list some signers emit. ReferenceResolver re-derives the target element
 * from each reference's own URI; DigestVerifier uses the method, canonicalization, prefixes and expected value
 * to verify the re-computed digest.
 *
 * A reference may also declare a transform that is not a canonicalization at all, but an indirection: the
 * digest was computed over an element the reference names rather than over the element it points at. Its URI
 * is recorded here so the resolver knows to hand the reference to the registered DereferencingTransform. The
 * canonicalization stays alongside it, because such a transform still names one for the element it resolves
 * to, and keeping it in the same field is what lets the algorithm allow-list gate it like any other.
 */
final readonly class ParsedReference
{
    /**
     * @param list<string> $inclusivePrefixes
     * @param non-empty-string|null $dereferencingTransform the ds:Transform/@Algorithm of the indirection this
     *        reference declared, or null for an ordinary in-document reference
     */
    public function __construct(
        public DigestMethod $digestMethod,
        public string $expectedDigestValueBase64,
        public SignatureCanonicalization $canonicalization,
        public array $inclusivePrefixes,
        public ?string $dereferencingTransform = null,
    ) {
    }
}
