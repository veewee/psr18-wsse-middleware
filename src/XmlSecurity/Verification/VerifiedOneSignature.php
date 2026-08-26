<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;

/**
 * What one verified ds:Signature contributed, before the orchestrator merges it with the others in its scope.
 *
 * Internal to the verification flow: a caller sees the union, as VerifiedSignature. It exists so the merge is
 * a named step over a named shape rather than four parallel arrays threaded through a loop.
 *
 * @internal
 */
final readonly class VerifiedOneSignature
{
    /**
     * @param list<Element>          $elements      the covered element instances, in reference order
     * @param list<non-empty-string> $ids           the bare id each reference used, in the same order
     * @param list<ExternalPart>     $externalParts the external parts this signature covered
     * @param ?TrustedSigner         $signer        null for a signature keyed by a symmetric secret, which
     *        names no party: one key both produces and checks it
     */
    public function __construct(
        public array $elements,
        public array $ids,
        public array $externalParts,
        public ?TrustedSigner $signer,
    ) {
    }
}
