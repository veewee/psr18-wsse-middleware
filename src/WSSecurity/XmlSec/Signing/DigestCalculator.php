<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\ResolvedReference;

/**
 * Canonicalizes one resolved element, then digests the canonical bytes. Returns a DigestResult the
 * SignedInfoBuilder can emit as ds:Reference. The base64 of the raw digest is applied here, so the builder
 * places the value verbatim.
 */
final class DigestCalculator
{
    public function __construct(
        private Canonicalizer $canonicalizer,
        private Digest $digest,
    ) {
    }

    /**
     * @throws CanonicalizationFailed when the element cannot be canonicalized (propagated from the canonicalizer)
     */
    public function calculate(
        ResolvedReference $reference,
        SignatureCanonicalization $method,
        DigestMethod $digestMethod,
    ): DigestResult {
        $canonical = $this->canonicalizer->canonicalize($reference->element, $method);

        // A digest is always fixed-length non-empty bytes, so its base64 is a non-empty string.
        $digest = base64_encode($this->digest->hash($canonical, $digestMethod));
        assert($digest !== '');

        return new DigestResult($reference->wsuId, $digest, $digestMethod);
    }
}
