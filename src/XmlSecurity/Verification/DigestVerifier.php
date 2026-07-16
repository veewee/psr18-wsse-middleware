<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;

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
    public function verify(ResolvedVerificationReference $reference): bool
    {
        $parsed = $reference->parsed;
        $expected = base64_decode($parsed->expectedDigestValueBase64, true);
        if ($expected === false) {
            throw SignatureVerificationFailed::withReason('The digest value is not valid base64.');
        }

        $canonical = $this->canonicalizer->canonicalize(
            $reference->element,
            $parsed->canonicalization,
            $parsed->inclusivePrefixes === [] ? null : $parsed->inclusivePrefixes,
        );
        $actual = $this->digest->hash($canonical, $parsed->digestMethod);

        return $this->digest->equals($expected, $actual);
    }
}
