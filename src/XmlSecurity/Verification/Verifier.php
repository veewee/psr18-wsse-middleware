<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\CertificateExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\KeyInfoResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OpenSslTrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\TrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\X509DataKeyInfoResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DereferencingTransform;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ResolvedVerificationReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignatureValidator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\SignedInfoParser;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Orchestrates signature verification. It locates the single ds:Signature directly inside the scope element the
 * caller hands over,
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
     * The id lookup resolves each ds:Reference (and any ds:KeyInfo token reference) back to its element. It
     * defaults to the engine's xml:id convention; the WS-Security profile injects the wsu:Id implementation.
     *
     * The key-info resolver decides which ds:KeyInfo shapes are understood, and defaults to plain XML-DSig: an
     * inline ds:X509Certificate. The WS-Security profile injects its own, which reads the token forms its spec
     * defines. It is handed the id lookup above per call, so the two cannot address different id attributes.
     *
     * The dereferencing transform, when a profile supplies one, is the one transform a reference may declare
     * that substitutes the element to digest instead of canonicalizing the one it points at. Absent it, such a
     * reference stays an unknown transform and is refused, which is the engine's own answer on plain XML-DSig.
     */
    public static function create(
        ?IdLookup $idLookup = null,
        ?KeyInfoResolver $keyInfo = null,
        ?DereferencingTransform $dereferencingTransform = null,
    ): self {
        // The signer and verifier share one canonicalizer instance because digesting and verifying read the
        // same canonical form.
        $canonicalizer = new DomCanonicalizer();
        $idLookup ??= AttributeIdConvention::xmlId()->lookup();

        return new self(
            new SignatureLocator(),
            new SignedInfoParser(),
            new AlgorithmPolicyEnforcer(),
            new CertificateExtractor($keyInfo ?? new X509DataKeyInfoResolver(), $idLookup),
            new ReferenceResolver($idLookup, $dereferencingTransform),
            new DigestVerifier($canonicalizer, new Digest()),
            new SignatureValidator($canonicalizer, new OpenSslSigner()),
            new OpenSslTrustResolver(new CertificateTrust()),
            $dereferencingTransform,
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
        private ?DereferencingTransform $dereferencingTransform = null,
    ) {
    }

    public function verify(Document $document, VerificationPolicy $policy, Element $scope): VerifiedSignature
    {
        $signature = $this->signatureLocator->locate($scope);
        $signedInfo = $this->signedInfoParser->parse($signature, $this->dereferencingTransform);

        $this->policyEnforcer->enforce($policy, $signedInfo);

        $chain = $this->certificateExtractor->extract($document, $signature, $policy->trustStore);
        $signer = $this->establishTrust($chain, $policy);
        $this->assertKeyStrongEnough($signer, $policy);

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

        // What a signature covered is what it digested, so a reference whose transform substituted the
        // element reports the substituted one. A caller asserting coverage by identity is asking about the
        // token, never about the indirection that named it.
        $elements = array_map(
            static fn (ResolvedVerificationReference $reference): Element => $reference->digested(),
            $resolved,
        );
        $ids = array_map(
            static fn (ResolvedVerificationReference $reference): string => $reference->id,
            $resolved,
        );

        return new VerifiedSignature(new VerifiedReferences($elements, $ids), $signer);
    }

    /**
     * The trust resolver is a replaceable seam, and the reason to replace it is to reach a corporate PKI or an
     * OCSP responder. Such a resolver raises types of its own -- a lookup miss, a timeout, a transport error --
     * so anything it throws collapses to the same refusal the in-tree one produces. Without that, a peer learns
     * from the exception it triggered whether the service knew its certificate, and often what the service is.
     * The original is chained for the operator log only.
     */
    private function establishTrust(
        CertificateChain $chain,
        VerificationPolicy $policy,
    ): TrustedSigner {
        try {
            return $this->trustResolver->verifyTrust($chain, $policy->trustStore);
        } catch (CertificateTrustException $exception) {
            throw SignatureVerificationFailed::withReason('The signer certificate is not trusted.', $exception);
        } catch (Throwable $foreign) {
            throw SignatureVerificationFailed::withReason('The signer certificate is not trusted.', $foreign);
        }
    }

    /**
     * A valid chain says nothing about how big the signer's key is, and OpenSSL's path validation carries no
     * key-size policy of its own, so the floor the crypto policy states is applied here. It runs with trust,
     * before any reference resolution or digesting, so a weak signer never learns which references resolved.
     *
     * @throws SignatureVerificationFailed
     */
    private function assertKeyStrongEnough(TrustedSigner $signer, VerificationPolicy $policy): void
    {
        try {
            $strength = $signer->certificate()->info()->publicKeyStrength();
        } catch (CryptoOperationFailed) {
            throw SignatureVerificationFailed::withReason('The signer certificate is not trusted.');
        }

        // A key that could not be read is refused here rather than deferred to the signature check. The two do
        // not share a parser: this verdict comes from ext-openssl while the signature is verified with
        // phpseclib, which has its own acceptance set and may well load a key openssl declined. Deferring
        // would leave the only check on signer key size unapplied for exactly the keys it cannot measure.
        if ($strength === null || !$policy->crypto->acceptsPublicKeyStrength($strength)) {
            throw SignatureVerificationFailed::withReason('The signer key is weaker than the policy accepts.');
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
