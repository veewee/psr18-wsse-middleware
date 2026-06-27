<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;

/**
 * A ds:Reference with its DOM element located: the exact element to re-canonicalize and re-digest, the
 * canonicalization and inclusive-namespaces prefix list its digest is computed under, plus the expected digest
 * value. The element is never re-looked-up after this point; the object identity of this instance is what later
 * proves which element instances the signature actually covered.
 */
final readonly class ResolvedVerificationReference
{
    /**
     * @param list<string> $inclusivePrefixes
     */
    public function __construct(
        public Element $element,
        public DigestMethod $digestMethod,
        public string $expectedDigestValueBase64,
        public SignatureCanonicalization $canonicalization,
        public array $inclusivePrefixes,
    ) {
    }
}
