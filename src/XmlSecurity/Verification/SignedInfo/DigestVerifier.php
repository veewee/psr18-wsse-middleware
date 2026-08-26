<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\ApexDefaultNamespace;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\Canonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartContent;

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

        // An enveloped-signature reference digests its element without the signature it contains. The resolver
        // has already established that this is the one signature the element holds and that it is the signature
        // being verified, so nothing here has to decide which node may be dropped.
        //
        // Which element is digested is the resolver's answer too: a reference whose transform substituted one
        // reports it, and this reads that rather than the element the reference URI named.
        $canonical = $this->canonicalizer->canonicalize(
            $reference->digested(),
            // Non-null for an in-document reference: the resolver routes an external one elsewhere.
            $parsed->canonicalization ?? throw SignatureVerificationFailed::withReason(
                'A reference declares no canonicalization.',
            ),
            $parsed->inclusivePrefixes === [] ? null : $parsed->inclusivePrefixes,
            $reference->envelopedSignature,
        );
        // A dereferenced reference's digest input always states the empty default namespace on its apex,
        // whatever was in scope. See ApexDefaultNamespace for why that is not the primitive's job.
        if ($reference->dereferenced !== null) {
            $canonical = ApexDefaultNamespace::emptied($canonical);
        }

        $actual = $this->digest->hash($canonical, $parsed->digestMethod);

        return $this->digest->equals($expected, $actual);
    }

    /**
     * Digests an external part's content under the same rule the signer applied to it and compares in
     * constant time: XML canonicalized, other text with its line endings normalized, anything else exactly as
     * it travels.
     *
     * XML content is canonicalized with exclusive C14N first, the same as the signer did, so a part whose
     * octets are not a readable document has no node-set to compare and is refused rather than guessed at.
     *
     * The stream is rewound first, because the same part may already have been read on this message: the
     * decryption block ran before this one and replaced these bytes.
     *
     * @throws SignatureVerificationFailed when the expected digest value is not valid base64, or the part is
     *         one whose canonicalization is not implemented
     */
    public function verifyExternalPart(ResolvedExternalReference $reference): bool
    {
        $expected = base64_decode($reference->parsed->expectedDigestValueBase64, true);
        if ($expected === false) {
            throw SignatureVerificationFailed::withReason('The digest value is not valid base64.');
        }

        $part = $reference->part;
        try {
            $octets = (new ExternalPartContent($this->canonicalizer))
                ->canonicalize($part->mimeType, $part->content->rewind()->getContents());
        } catch (CanonicalizationFailed $exception) {
            throw SignatureVerificationFailed::withReason(
                'A referenced part could not be read as the media type it declares.',
                $exception,
            );
        }

        $actual = $this->digest->hash($octets, $reference->parsed->digestMethod);
        // Left rewound rather than at EOF. This is the caller's own attachment stream, and verifying it is
        // not supposed to consume it: the next reader is usually the application.
        $part->content->rewind();

        return $this->digest->equals($expected, $actual);
    }
}
