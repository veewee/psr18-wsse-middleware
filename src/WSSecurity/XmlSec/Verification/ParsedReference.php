<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;

/**
 * The data read from one ds:Reference: the declared DigestMethod, the expected base64 digest value exactly as
 * it appears in ds:DigestValue, and the canonicalization this reference's digest is computed under together
 * with the inclusive-namespaces prefix list some signers emit. ReferenceResolver re-derives the target element
 * from each reference's own URI; DigestVerifier uses the method, canonicalization, prefixes and expected value
 * to verify the re-computed digest.
 */
final readonly class ParsedReference
{
    /**
     * @param list<string> $inclusivePrefixes
     */
    public function __construct(
        public DigestMethod $digestMethod,
        public string $expectedDigestValueBase64,
        public SignatureCanonicalization $canonicalization,
        public array $inclusivePrefixes,
    ) {
    }
}
