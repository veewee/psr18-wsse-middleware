<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * The evidence a signature verification produced: which elements were signed (by exact instance) and which
 * trusted signer produced the signature. Returned instead of a bare boolean so the caller asserts coverage and
 * trust explicitly.
 */
final readonly class VerifiedSignature
{
    public function __construct(
        public VerifiedReferences $signedElements,
        public TrustedSigner $signer,
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
