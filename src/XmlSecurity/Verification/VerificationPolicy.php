<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;

/**
 * The policy a signature is verified against: the trust anchors plus the algorithm policy whose allow-lists
 * gate every algorithm the signature names. The pair is carried as-is: the CryptoPolicy answers acceptance
 * itself, so no allow-list is ever copied out of it.
 *
 * This DTO supplies the trust store and the algorithm policy; whether the required parts are in the
 * signed set is asserted by the Inbound\VerifySignature block against the returned VerifiedReferences,
 * not here. The verifier reports, the policy block decides.
 */
final readonly class VerificationPolicy
{
    /**
     * @param ?ExternalPartVerification $externalParts the parts a cid: reference may resolve to, and the
     *        transform it must declare. Absent means every non-fragment reference URI stays refused
     */
    public function __construct(
        public TrustStore $trustStore,
        public CryptoPolicy $crypto,
        public ?ExternalPartVerification $externalParts = null,
    ) {
    }
}
