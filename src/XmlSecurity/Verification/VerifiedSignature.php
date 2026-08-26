<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;

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
    ) {
    }
}
