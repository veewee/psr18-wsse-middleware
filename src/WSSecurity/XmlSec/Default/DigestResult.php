<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;

/**
 * The canonicalized digest for one ds:Reference: the element's wsu:Id (without '#'), the base64-encoded
 * digest value, and the DigestMethod URI. SignedInfoBuilder uses these three fields to emit ds:Reference.
 */
final readonly class DigestResult
{
    /**
     * @param non-empty-string $wsuId            the bare id value, without the '#' fragment prefix
     * @param non-empty-string $digestValueBase64 the base64 of the raw digest bytes, ready for ds:DigestValue
     */
    public function __construct(
        public string $wsuId,
        public string $digestValueBase64,
        public DigestMethod $digestMethod,
    ) {
    }
}
