<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;

/**
 * The canonicalized digest for one ds:Reference: the element's id (without '#'), the base64-encoded
 * digest value, and the DigestMethod URI. SignedInfoBuilder uses these three fields to emit ds:Reference.
 */
final readonly class DigestResult
{
    /**
     * @param non-empty-string $id                the bare id value, without the '#' fragment prefix
     * @param non-empty-string $digestValueBase64 the base64 of the raw digest bytes, ready for ds:DigestValue
     */
    public function __construct(
        public string $id,
        public string $digestValueBase64,
        public DigestMethod $digestMethod,
    ) {
    }
}
