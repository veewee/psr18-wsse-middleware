<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;

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
        $crypto = $policy->crypto;

        if (!$crypto->acceptsSignatureMethod($signedInfo->signatureMethod)) {
            throw SignatureVerificationFailed::withReason('The signature method is not accepted by the policy.');
        }

        if (!$crypto->acceptsCanonicalization($signedInfo->canonicalization)) {
            throw SignatureVerificationFailed::withReason('The canonicalization method is not accepted by the policy.');
        }

        foreach ($signedInfo->references as $reference) {
            if (!$crypto->acceptsDigestMethod($reference->digestMethod)) {
                throw SignatureVerificationFailed::withReason('A digest method is not accepted by the policy.');
            }

            // An external reference declares no canonicalization to gate: its transform selects octets, and
            // that the transform is exactly the expected one was already established while parsing. Its digest
            // method is checked above, like every other reference's.
            if ($reference->canonicalization !== null
                && !$crypto->acceptsCanonicalization($reference->canonicalization)) {
                throw SignatureVerificationFailed::withReason('The canonicalization method is not accepted by the policy.');
            }
        }
    }
}
