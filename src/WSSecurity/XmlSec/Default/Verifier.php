<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\CertificateChain;
use Soap\Psr18WsseMiddleware\WSSecurity\Trust\TrustedSigner;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseXpath;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\VerificationPolicy;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Result\VerifiedReferences;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Result\VerifiedSignature;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\XmlSignatureVerifier;
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
        private CertificateExtractor $certificateExtractor,
        private ReferenceResolver $referenceResolver,
        private DigestVerifier $digestVerifier,
        private SignatureValidator $signatureValidator,
        private KeyResolver $keyResolver,
    ) {
    }

    public function verify(Document $document, VerificationPolicy $policy): VerifiedSignature
    {
        $signature = $this->locateSignature($document);
        $signedInfo = $this->requireDsChild($signature, 'SignedInfo');

        $canonicalization = $this->signatureCanonicalization($signedInfo);
        $signatureMethod = $this->signatureMethod($signedInfo);
        [$referenceElements, $parsedReferences] = $this->parseReferences($signedInfo);

        $this->enforcePolicy($policy, $signatureMethod, $canonicalization, $parsedReferences);

        $chain = $this->certificateExtractor->extract($document, $signature);
        $signer = $this->establishTrust($chain, $policy);

        $resolved = $this->referenceResolver->resolve($document, $referenceElements, $parsedReferences, $signature);

        $this->verifyDigests($resolved, $canonicalization);

        if (!$this->signatureValidator->validate($signature, $signer->certificate(), $signatureMethod, $canonicalization)) {
            throw SignatureVerificationFailed::withReason('The signature value did not verify.');
        }

        $elements = array_map(
            static fn (ResolvedVerificationReference $reference): Element => $reference->element,
            $resolved,
        );

        return new VerifiedSignature(new VerifiedReferences($elements), $signer);
    }

    private function locateSignature(Document $document): Element
    {
        $signatures = $document
            ->xpath(new WsseXpath($document))
            ->query(
                '//'.WsseNamespace::Wsse->qualify('Security').'/'.WsseNamespace::Ds->qualify('Signature'),
            )
            ->expectAllOfType(Element::class);

        if ($signatures->count() !== 1) {
            throw SignatureVerificationFailed::withReason(
                'Exactly one ds:Signature is required in the Security header.',
            );
        }

        return $signatures->expectSingle();
    }

    /**
     * @return array{0: non-empty-list<Element>, 1: non-empty-list<ParsedReference>}
     */
    private function parseReferences(Element $signedInfo): array
    {
        $elements = [];
        $parsed = [];
        foreach ($this->childElements($signedInfo) as $child) {
            if ($child->localName !== 'Reference' || $child->namespaceURI !== WsseNamespace::Ds->value) {
                continue;
            }

            $elements[] = $child;
            $parsed[] = $this->parseReference($child);
        }

        if ($elements === [] || $parsed === []) {
            throw SignatureVerificationFailed::withReason('The signature declares no references.');
        }

        return [$elements, $parsed];
    }

    private function parseReference(Element $reference): ParsedReference
    {
        $uri = (string) $reference->getAttribute('URI');
        if (!str_starts_with($uri, '#') || $uri === '#') {
            throw SignatureVerificationFailed::withReason('A reference URI must be a non-empty same-document id.');
        }

        $wsuId = substr($uri, 1);
        if ($wsuId === '') {
            throw SignatureVerificationFailed::withReason('A reference URI must be a non-empty same-document id.');
        }

        $digestMethod = $this->digestMethod($reference);
        $digestValue = $this->requireDsChild($reference, 'DigestValue');

        return new ParsedReference($wsuId, $digestMethod, trim((string) $digestValue->textContent));
    }

    /**
     * @param non-empty-list<ParsedReference> $parsedReferences
     */
    private function enforcePolicy(
        VerificationPolicy $policy,
        SignatureMethod $signatureMethod,
        SignatureCanonicalization $canonicalization,
        array $parsedReferences,
    ): void {
        if (!in_array($signatureMethod, $policy->acceptedSignatureMethods, true)) {
            throw SignatureVerificationFailed::withReason('The signature method is not accepted by the policy.');
        }

        if (!in_array($canonicalization, $policy->acceptedCanonicalizations, true)) {
            throw SignatureVerificationFailed::withReason('The canonicalization method is not accepted by the policy.');
        }

        foreach ($parsedReferences as $reference) {
            if (!in_array($reference->digestMethod, $policy->acceptedDigestMethods, true)) {
                throw SignatureVerificationFailed::withReason('A digest method is not accepted by the policy.');
            }
        }
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

    private function signatureCanonicalization(Element $signedInfo): SignatureCanonicalization
    {
        $method = $this->requireDsChild($signedInfo, 'CanonicalizationMethod');
        $algorithm = SignatureCanonicalization::tryFrom((string) $method->getAttribute('Algorithm'));

        return $algorithm
            ?? throw SignatureVerificationFailed::withReason('The canonicalization method is unknown.');
    }

    private function signatureMethod(Element $signedInfo): SignatureMethod
    {
        $method = $this->requireDsChild($signedInfo, 'SignatureMethod');
        $algorithm = SignatureMethod::tryFrom((string) $method->getAttribute('Algorithm'));

        return $algorithm
            ?? throw SignatureVerificationFailed::withReason('The signature method is unknown.');
    }

    private function digestMethod(Element $reference): DigestMethod
    {
        $method = $this->requireDsChild($reference, 'DigestMethod');
        $algorithm = DigestMethod::tryFrom((string) $method->getAttribute('Algorithm'));

        return $algorithm
            ?? throw SignatureVerificationFailed::withReason('A digest method is unknown.');
    }

    private function requireDsChild(Element $parent, string $localName): Element
    {
        // Exactly one, so a second injected ds:DigestMethod/ds:DigestValue cannot shadow the real one.
        $found = null;
        foreach ($this->childElements($parent) as $child) {
            if ($child->localName !== $localName || $child->namespaceURI !== WsseNamespace::Ds->value) {
                continue;
            }

            if ($found !== null) {
                throw SignatureVerificationFailed::withReason(sprintf('ds:%s must appear exactly once.', $localName));
            }

            $found = $child;
        }

        return $found
            ?? throw SignatureVerificationFailed::withReason(sprintf('ds:%s is missing.', $localName));
    }

    /**
     * @return list<Element>
     */
    private function childElements(Element $parent): array
    {
        $elements = [];
        /** @var \Dom\Node $child */
        foreach ($parent->childNodes as $child) {
            if ($child instanceof Element) {
                $elements[] = $child;
            }
        }

        return $elements;
    }
}
