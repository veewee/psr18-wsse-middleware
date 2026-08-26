<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Dom\Element;

/**
 * A ds:Reference with its DOM element located: the parsed reference data (DigestMethod, expected digest,
 * canonicalization and inclusive-namespaces prefix list), the bare id from the reference URI, the exact
 * element to re-canonicalize and re-digest, and. When the reference declares the enveloped-signature
 * transform. The one ds:Signature to leave out of that element's digest. The element is never re-looked-up after this point; the object
 * identity of this instance is what later proves which element instances the signature actually covered.
 *
 * A reference whose transform substituted the element before digesting carries both: the element the URI named,
 * which says which reference this was, and the dereferenced one, which is what was actually digested and
 * therefore what the signature covered.
 */
final readonly class ResolvedVerificationReference
{
    /**
     * @param non-empty-string $id the bare id from the reference URI, without the '#' fragment prefix
     */
    public function __construct(
        public ParsedReference $parsed,
        public Element $element,
        public string $id,
        public ?Element $envelopedSignature = null,
        public ?Element $dereferenced = null,
    ) {
    }

    /**
     * The element whose canonical form the digest was computed over. That is the reference's own element for
     * every ordinary reference, and the dereferenced one where a transform substituted it.
     */
    public function digested(): Element
    {
        return $this->dereferenced ?? $this->element;
    }
}
