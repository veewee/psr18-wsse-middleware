<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;

/**
 * A ds:Reference with its DOM element located: the parsed reference data (DigestMethod, expected digest,
 * canonicalization and inclusive-namespaces prefix list), the bare id from the reference URI, and the exact
 * element to re-canonicalize and re-digest. The element is never re-looked-up after this point; the object
 * identity of this instance is what later proves which element instances the signature actually covered.
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
    ) {
    }
}
