<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustedSigner;
use VeeWee\Xml\Dom\Document;

/**
 * Orchestrates WSSE signature verification. It locates the single ds:Signature in the wsse:Security header,
 * enforces the policy algorithm allow-lists before any expensive work, extracts the signer certificate from
 * the message, establishes trust against the policy trust store, resolves every reference to its exact DOM
 * element, verifies all digests, verifies the signature value, and returns the verified references together
 * with the trusted signer.
 *
 * The step order is security-critical. Allow-list and trust run before reference resolution and crypto, so a
 * disallowed algorithm or an untrusted signer is rejected before the verifier reveals which references
 * resolved. Digests are verified before the signature value. The resolved element instances are carried
 * straight into the result so a later coverage check compares the exact objects the signature covered.
 *
 * Every detected failure, whatever its cause, surfaces as one SignatureVerificationFailed with a
 * non-identifying message, so the exception cannot be used as a forgery oracle. A canonicalization failure
 * propagates unchanged.
 */
final class Verifier implements XmlSignatureVerifier
{
    public function __construct(
        private SignatureLocator $signatureLocator,
        private SignedInfoParser $signedInfoParser,
        private AlgorithmPolicyEnforcer $policyEnforcer,
        private CertificateExtractor $certificateExtractor,
        private ReferenceResolver $referenceResolver,
        private DigestVerifier $digestVerifier,
        private SignatureValidator $signatureValidator,
        private KeyResolver $keyResolver,
    ) {
    }

    public function verify(Document $document, VerificationPolicy $policy): VerifiedSignature
    {
        $signature = $this->signatureLocator->locate($document);
        $signedInfo = $this->signedInfoParser->parse($signature);

        $this->policyEnforcer->enforce($policy, $signedInfo);

        $chain = $this->certificateExtractor->extract($document, $signature);
        $signer = $this->establishTrust($chain, $policy);

        $resolved = $this->referenceResolver->resolve(
            $document,
            $signedInfo->referenceElements,
            $signedInfo->references,
            $signature,
        );

        $this->verifyDigests($resolved, $signedInfo->canonicalization);

        if (!$this->signatureValidator->validate(
            $signature,
            $signer->certificate(),
            $signedInfo->signatureMethod,
            $signedInfo->canonicalization,
        )) {
            throw SignatureVerificationFailed::withReason('The signature value did not verify.');
        }

        $elements = array_map(
            static fn (ResolvedVerificationReference $reference): Element => $reference->element,
            $resolved,
        );

        return new VerifiedSignature(new VerifiedReferences($elements), $signer);
    }

    private function establishTrust(
        CertificateChain $chain,
        VerificationPolicy $policy,
    ): TrustedSigner {
        try {
            return $this->keyResolver->verifyTrust($chain, $policy->trustStore);
        } catch (CertificateTrustException) {
            throw SignatureVerificationFailed::withReason('The signer certificate is not trusted.');
        }
    }

    /**
     * @param non-empty-list<ResolvedVerificationReference> $resolved
     */
    private function verifyDigests(array $resolved, SignatureCanonicalization $canonicalization): void
    {
        foreach ($resolved as $reference) {
            if (!$this->digestVerifier->verify($reference, $canonicalization)) {
                throw SignatureVerificationFailed::withReason('A reference digest did not match.');
            }
        }
    }
}
