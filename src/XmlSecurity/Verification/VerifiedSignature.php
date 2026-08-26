<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * The evidence a verification produced: which elements were signed (by exact instance) and which trusted signers
 * produced the signatures covering them. Returned instead of a bare boolean so the caller asserts coverage and
 * trust explicitly.
 *
 * A scope may carry more than one signature, and every one of them verified, so this is the union of what they
 * covered and the list of who signed. An endorsing supporting token is the ordinary case: one signature covers
 * the Body and a second covers the first.
 *
 * A signature keyed by a symmetric secret contributes no signer: one key both produces and checks it, so it
 * names no party. A message signed only that way therefore has an empty signer list, and a caller that wanted
 * an identity has to notice rather than be handed a stand-in.
 */
final readonly class VerifiedSignature
{
    /**
     * @param list<TrustedSigner> $signers one per signature that named a certificate, in document order
     */
    public function __construct(
        public VerifiedReferences $signedElements,
        public array $signers,
        private ?ExternalPartList $externalParts = null,
    ) {
    }

    /**
     * The external parts this signature actually covered, so a caller that registered some can assert every
     * one of them was signed rather than assume it. Empty for a message with none, which is the usual case.
     */
    public function signedExternalParts(): ExternalPartList
    {
        return $this->externalParts ?? ExternalPartList::of();
    }
}
