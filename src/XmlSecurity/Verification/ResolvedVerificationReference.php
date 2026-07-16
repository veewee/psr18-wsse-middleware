<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;

/**
 * A ds:Reference with its DOM element located: the parsed reference data (DigestMethod, expected digest,
 * canonicalization and inclusive-namespaces prefix list) plus the exact element to re-canonicalize and
 * re-digest. The element is never re-looked-up after this point; the object identity of this instance is what
 * later proves which element instances the signature actually covered.
 */
final readonly class ResolvedVerificationReference
{
    public function __construct(
        public ParsedReference $parsed,
        public Element $element,
    ) {
    }
}
