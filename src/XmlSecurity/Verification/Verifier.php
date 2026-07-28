<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OpenSslTrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\TrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ResolvedVerificationReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureValidator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use Soap\Psr18WsseMiddleware\XmlSecurity\XmlIdLookup;
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
    /**
     * The id lookup resolves each ds:Reference (and the ds:KeyInfo token reference) back to its element. It
     * defaults to the engine's xml:id convention; the WS-Security profile injects the wsu:Id implementation.
     */
    public static function create(?IdLookup $idLookup = null): self
    {
        // The signer and verifier share one canonicalizer instance because digesting and verifying read the
        // same canonical form.
        $canonicalizer = new DomCanonicalizer();
        $idLookup ??= new XmlIdLookup();

        return new self(
            new SignatureLocator(),
            new SignedInfoParser(),
            new AlgorithmPolicyEnforcer(),
            new CertificateExtractor($idLookup),
            new ReferenceResolver($idLookup),
            new DigestVerifier($canonicalizer, new Digest()),
            new SignatureValidator($canonicalizer, new OpenSslSigner()),
            new OpenSslTrustResolver(new CertificateTrust()),
        );
    }

    public function __construct(
        private SignatureLocator $signatureLocator,
        private SignedInfoParser $signedInfoParser,
        private AlgorithmPolicyEnforcer $policyEnforcer,
        private CertificateExtractor $certificateExtractor,
        private ReferenceResolver $referenceResolver,
        private DigestVerifier $digestVerifier,
        private SignatureValidator $signatureValidator,
        private TrustResolver $trustResolver,
    ) {
    }

    public function verify(Document $document, VerificationPolicy $policy, Element $scope): VerifiedSignature
    {
        $signature = $this->signatureLocator->locate($scope);
        $signedInfo = $this->signedInfoParser->parse($signature);

        $this->policyEnforcer->enforce($policy, $signedInfo);

        $chain = $this->certificateExtractor->extract($document, $signature, $policy->trustStore);
        $signer = $this->establishTrust($chain, $policy);

        $resolved = $this->referenceResolver->resolve(
            $document,
            $signedInfo->referenceElements,
            $signedInfo->references,
            $signature,
        );

        $this->verifyDigests($resolved);

        if (!$this->signatureValidator->validate(
            $signature,
            $signer->certificate(),
            $signedInfo->signatureMethod,
            $signedInfo->canonicalization,
            $signedInfo->canonicalizationInclusivePrefixes,
        )) {
            throw SignatureVerificationFailed::withReason('The signature value did not verify.');
        }

        $elements = array_map(
            static fn (ResolvedVerificationReference $reference): Element => $reference->element,
            $resolved,
        );
        $ids = array_map(
            static fn (ResolvedVerificationReference $reference): string => $reference->id,
            $resolved,
        );

        return new VerifiedSignature(new VerifiedReferences($elements, $ids), $signer);
    }

    private function establishTrust(
        CertificateChain $chain,
        VerificationPolicy $policy,
    ): TrustedSigner {
        try {
            return $this->trustResolver->verifyTrust($chain, $policy->trustStore);
        } catch (CertificateTrustException) {
            throw SignatureVerificationFailed::withReason('The signer certificate is not trusted.');
        }
    }

    /**
     * @param non-empty-list<ResolvedVerificationReference> $resolved
     */
    private function verifyDigests(array $resolved): void
    {
        foreach ($resolved as $reference) {
            if (!$this->digestVerifier->verify($reference)) {
                throw SignatureVerificationFailed::withReason('A reference digest did not match.');
            }
        }
    }
}
