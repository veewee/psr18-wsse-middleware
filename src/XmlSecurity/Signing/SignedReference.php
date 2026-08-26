<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;

/**
 * One ds:Reference ready to emit: what it points at, what it digests to, and the transform chain it was
 * digested under.
 *
 * The URI and the transforms are fields rather than rules because there is more than one kind of reference.
 * An element reference points at '#Body-1' and declares the canonicalization it was digested with; an
 * external part points at 'cid:invoice@example.com' and declares a transform that canonicalizes nothing.
 * SignedInfoBuilder emits exactly what it is handed and derives neither, so a new kind of reference needs no
 * change there.
 */
final readonly class SignedReference
{
    /**
     * @param non-empty-string                $uri               emitted verbatim, fragment prefix included when it has one
     * @param non-empty-string                $digestValueBase64 the base64 of the raw digest, ready for ds:DigestValue
     * @param non-empty-list<SignedTransform> $transforms        declared in the order they were applied
     */
    public function __construct(
        public string $uri,
        public string $digestValueBase64,
        public DigestMethod $digestMethod,
        public array $transforms,
    ) {
    }
}
