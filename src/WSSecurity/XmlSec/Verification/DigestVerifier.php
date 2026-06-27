<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Canonicalization\Canonicalizer;

/**
 * Re-canonicalizes one resolved element with the same method the signature declared, digests the canonical
 * bytes, and compares against the expected value with a constant-time comparison.
 *
 * A digest mismatch is a normal cryptographic outcome reported as false, not an exception; only a genuinely
 * malformed expected value (not valid base64) is refused outright. A canonicalization failure is a structural
 * error and propagates unchanged.
 */
final class DigestVerifier
{
    public function __construct(
        private Canonicalizer $canonicalizer,
        private Digest $digest,
    ) {
    }

    /**
     * @throws CanonicalizationFailed when the element cannot be canonicalized (propagated)
     * @throws SignatureVerificationFailed when the expected digest value is not valid base64
     */
    public function verify(
        ResolvedVerificationReference $reference,
        SignatureCanonicalization $canonicalizationMethod,
    ): bool {
        $expected = base64_decode($reference->expectedDigestValueBase64, true);
        if ($expected === false) {
            throw SignatureVerificationFailed::withReason('The digest value is not valid base64.');
        }

        $canonical = $this->canonicalizer->canonicalize($reference->element, $canonicalizationMethod);
        $actual = $this->digest->hash($canonical, $reference->digestMethod);

        return $this->digest->equals($expected, $actual);
    }
}
