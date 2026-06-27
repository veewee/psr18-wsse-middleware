<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;

/**
 * The data read from one ds:Reference: the bare wsu:Id (without '#'), the declared DigestMethod, and the
 * expected base64 digest value exactly as it appears in ds:DigestValue. ReferenceResolver uses the id to
 * locate the element; DigestVerifier uses the method and expected value to verify the re-computed digest.
 */
final readonly class ParsedReference
{
    /**
     * @param non-empty-string $wsuId
     */
    public function __construct(
        public string $wsuId,
        public DigestMethod $digestMethod,
        public string $expectedDigestValueBase64,
    ) {
    }
}
