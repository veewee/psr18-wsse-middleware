<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustStore;

/**
 * The policy a signature is verified against: the trust anchors plus the accepted-algorithm allow-lists. The
 * allow-lists are non-empty by type (an empty allow-list would accept nothing, which a caller must not be able
 * to express by accident); the default profiles populate them.
 *
 * This DTO reports the accepted algorithms and supplies the trust store; whether the required parts are in the
 * signed set is asserted by the Inbound\VerifySignature block (E2) against the returned VerifiedReferences,
 * not here. The verifier reports, the policy block decides.
 */
final readonly class VerificationPolicy
{
    /**
     * @param non-empty-list<SignatureMethod> $acceptedSignatureMethods
     * @param non-empty-list<DigestMethod> $acceptedDigestMethods
     * @param non-empty-list<SignatureCanonicalization> $acceptedCanonicalizations
     */
    public function __construct(
        public TrustStore $trustStore,
        public array $acceptedSignatureMethods,
        public array $acceptedDigestMethods,
        public array $acceptedCanonicalizations,
    ) {
    }
}
