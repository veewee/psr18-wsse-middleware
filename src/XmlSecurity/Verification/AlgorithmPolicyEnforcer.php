<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;

/**
 * Enforces the verification policy allow-lists against a parsed ds:SignedInfo: the SignatureMethod, the
 * CanonicalizationMethod, every reference DigestMethod, and every reference Transform canonicalization must
 * each be accepted by the policy. The canonicalization allow-list gates both the SignedInfo method and each
 * reference transform uniformly, so an inclusive c14n cannot slip in through a reference when the policy
 * accepts only exclusive c14n.
 *
 * This runs before any reference resolution or crypto, so a disallowed algorithm is rejected before the
 * verifier reveals which references resolved. A disallowed algorithm surfaces as one
 * SignatureVerificationFailed with a non-identifying message.
 */
final class AlgorithmPolicyEnforcer
{
    /**
     * @throws SignatureVerificationFailed
     */
    public function enforce(VerificationPolicy $policy, ParsedSignedInfo $signedInfo): void
    {
        if (!in_array($signedInfo->signatureMethod, $policy->acceptedSignatureMethods, true)) {
            throw SignatureVerificationFailed::withReason('The signature method is not accepted by the policy.');
        }

        if (!in_array($signedInfo->canonicalization, $policy->acceptedCanonicalizations, true)) {
            throw SignatureVerificationFailed::withReason('The canonicalization method is not accepted by the policy.');
        }

        foreach ($signedInfo->references as $reference) {
            if (!in_array($reference->digestMethod, $policy->acceptedDigestMethods, true)) {
                throw SignatureVerificationFailed::withReason('A digest method is not accepted by the policy.');
            }

            if (!in_array($reference->canonicalization, $policy->acceptedCanonicalizations, true)) {
                throw SignatureVerificationFailed::withReason('The canonicalization method is not accepted by the policy.');
            }
        }
    }
}
