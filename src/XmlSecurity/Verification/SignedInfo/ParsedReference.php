<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

/**
 * The data read from one ds:Reference: the declared DigestMethod, the expected base64 digest value exactly as
 * it appears in ds:DigestValue, and how the digest was computed. ReferenceResolver re-derives what the
 * reference points at from its own URI; DigestVerifier uses these values to verify the re-computed digest.
 *
 * How the digest was computed takes one of exactly two forms, which is why both fields are nullable and
 * exactly one is set. An in-document reference names a canonicalization, with the inclusive-namespaces prefix
 * list some signers emit. An external reference names a transform that is not a canonicalization at all: it
 * selects an attachment's octets, and canonicalizing them is precisely what must not happen.
 *
 * An in-document reference may also declare a transform that is not a canonicalization either, but an
 * indirection: the digest was computed over an element the reference names rather than over the element it
 * points at. Its URI is recorded here so the resolver knows to hand the reference to the registered
 * DereferencingTransform. The canonicalization stays alongside it, because such a transform still names one
 * for the element it resolves to, and keeping it in the same field is what lets the algorithm allow-list gate
 * it like any other.
 */
final readonly class ParsedReference
{
    /**
     * @param list<string>          $inclusivePrefixes
     * @param non-empty-string|null $externalTransform
     * @param non-empty-string|null $dereferencingTransform the ds:Transform/@Algorithm of the indirection this
     *        reference declared, or null for an ordinary in-document reference
     *
     * @throws InvalidArgumentException unless exactly one of canonicalization and externalTransform is set
     * @throws InvalidArgumentException if an external reference also declares an indirection
     */
    public function __construct(
        public DigestMethod $digestMethod,
        public string $expectedDigestValueBase64,
        public ?SignatureCanonicalization $canonicalization,
        public array $inclusivePrefixes,
        public ?string $externalTransform = null,
        public ?string $dereferencingTransform = null,
    ) {
        if (($canonicalization === null) === ($externalTransform === null)) {
            // Neither would leave the digest's computation undefined; both would leave two answers for how it
            // was computed, and a verifier picking one of them is a verifier a signer can steer.
            throw new InvalidArgumentException(
                'A reference is digested either under a canonicalization or under an external transform.',
            );
        }

        if ($externalTransform !== null && $dereferencingTransform !== null) {
            // The two together would leave the digest with two definitions again, one over octets and one
            // over whatever element the indirection resolved to.
            throw new InvalidArgumentException(
                'An external reference names octets, so there is no element for an indirection to resolve to.',
            );
        }
    }

    public function isExternal(): bool
    {
        return $this->externalTransform !== null;
    }
}
