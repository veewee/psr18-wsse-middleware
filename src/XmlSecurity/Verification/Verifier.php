<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\OpenSSL\Signer as OpenSslSigner;
use Soap\Psr18WsseMiddleware\XmlSecurity\AttributeIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization\DomCanonicalizer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\KeyInfoResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OpenSslTrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\TrustResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\VerificationKey;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\VerificationKeyExtractor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\X509DataKeyInfoResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\AlgorithmPolicyEnforcer;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DereferencingTransform;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\DigestVerifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ReferenceResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ResolvedExternalReference;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo\ResolvedReferences;
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
 * A signature keyed by a symmetric secret has no signer and no chain to establish trust over: the secret is
 * its own evidence, since only this exchange could have established it. What the two paths share is the guard
 * between them, and it is the reason the kind of key is checked against the signature method rather than the
 * other way round: an HMAC method answered with a certificate would be verified against public bytes anyone
 * holds, and an asymmetric method answered with a secret would skip the trust decision entirely.
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
            new VerificationKeyExtractor($keyInfo ?? new X509DataKeyInfoResolver(), $idLookup),
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
        private VerificationKeyExtractor $verificationKeyExtractor,
        private ReferenceResolver $referenceResolver,
        private DigestVerifier $digestVerifier,
        private SignatureValidator $signatureValidator,
        private TrustResolver $trustResolver,
        private ?DereferencingTransform $dereferencingTransform = null,
    ) {
    }

    public function verify(Document $document, VerificationPolicy $policy, Element $scope): VerifiedSignature
    {
        $elements = [];
        $ids = [];
        $externalParts = [];
        $signers = [];

        // Every signature the scope carries, and every one of them has to verify. What a caller may rely on is
        // the union of what they covered, which is what makes an endorsing supporting token work: the primary
        // signature covers the Body, the endorsement covers the primary. An injected extra signature is not an
        // alternative to validate, it is one more thing that must hold, so it refuses the message.
        $verifiedSignatures = [];
        foreach ($this->signatureLocator->locate($scope) as $signature) {
            $verifiedSignatures[] = $this->verifyOne($document, $policy, $signature);
        }

        $signatureElements = array_map(
            static fn (VerifiedOneSignature $verified): Element => $verified->signature,
            $verifiedSignatures,
        );

        $this->assertOneContributingParty($verifiedSignatures, $signatureElements);

        foreach ($verifiedSignatures as $verified) {
            // An endorsement's own coverage does not join the union. It vouches for a signature, and a peer
            // legitimately covers more alongside it: a CXF endorsement under sp:ProtectTokens also covers its
            // own token, and a supporting token may declare signed parts of its own. Pooling those would let
            // the endorsing party's word satisfy a requirement the endorsed party never met, which is the same
            // conflation the one-party rule exists to prevent. So the signatures it endorsed are reported and
            // the rest is not, and a caller wanting those parts has to see them covered by the party that sent
            // the message.
            $endorsing = self::endorses($verified->elements, $signatureElements);
            $reported = $endorsing
                ? self::signaturesAmong($verified->elements, $signatureElements)
                : array_keys($verified->elements);

            foreach ($reported as $index) {
                $elements[] = $verified->elements[$index];
                // Paired by index with the element, as VerifiedReferences states, so the two are filtered
                // together or not at all. A reference resolving to an element resolved it by an id.
                $ids[] = $verified->ids[$index];
            }

            if (!$endorsing) {
                $externalParts = [...$externalParts, ...$verified->externalParts];
            }
            if ($verified->signer !== null) {
                $signers[] = $verified->signer;
            }
        }

        return new VerifiedSignature(
            new VerifiedReferences($elements, $ids),
            $signers,
            ExternalPartList::of(...$externalParts),
        );
    }

    /**
     * Every signature that contributes coverage to one scope must be by the same party.
     *
     * Without this the union of coverage would span parties. Where trust is anchored on a CA rather than pinned
     * to the peer, anyone holding a certificate that CA issued can produce a signature this verifier accepts, so
     * they could append their own token and a signature over it to a message the real peer signed. A coverage
     * requirement naming the Security header contents would then be satisfied partly by the peer and partly by
     * the attacker, and a caller reading "every token was signed" would have no way to tell.
     *
     * A party is a certificate, or the holder of a secret this exchange established. Counting the secret is what
     * makes the rule reach the shape it matters most in: a MAC names no certificate, so a rule stated over
     * signers alone sees one signer in a scope where two parties signed.
     *
     * An endorsement is exempt, which is the whole reason the rule is about contribution rather than about
     * signing: an endorsing token belongs to the sender and legitimately differs from the party whose signature
     * it endorses. What keeps the exemption from being the hole reopened is not a narrow test here but that an
     * endorsement's own coverage never joins the union, in verify(): a signature covering the primary *and* a
     * part of its own choosing is exempt from this count and has that part discarded, so there is nothing to
     * launder either way.
     *
     * Covering a verified signature is the whole test, deliberately, because it is the one a peer answers to.
     * It is what CXF requires of an endorsing supporting token, and a peer covers more alongside the primary
     * signature as a matter of course: under sp:ProtectTokens its endorsement also covers its own token.
     *
     * A message genuinely signed by two contributing identities, a countersignature by a notary say, is refused
     * rather than merged, because which parts each of them vouched for is a question this reports no answer to.
     *
     * @param list<VerifiedOneSignature> $verifiedSignatures
     * @param list<Element>              $signatureElements
     *
     * @throws SignatureVerificationFailed
     */
    private function assertOneContributingParty(array $verifiedSignatures, array $signatureElements): void
    {
        $certificates = [];
        $secretParty = false;
        foreach ($verifiedSignatures as $verified) {
            if (self::endorsesOnlySecretKeyed($verified, $verifiedSignatures, $signatureElements)) {
                continue;
            }

            if ($verified->signer === null) {
                // Every secret in a scope was established by this exchange, so they are all the one party this
                // exchange shares them with.
                $secretParty = true;

                continue;
            }

            $certificates[$verified->signer->certificate()->toBase64Der()] = true;
        }

        if (count($certificates) + (int) $secretParty > 1) {
            throw SignatureVerificationFailed::withReason('The scope carries signatures from more than one party.');
        }
    }

    /**
     * Whether a signature may skip the party count, which is only when every signature it endorses is keyed by
     * a secret.
     *
     * Covering a verified signature is what an endorsement looks like, and it is not enough on its own. Where
     * trust is anchored on a CA, anyone that CA issued a certificate to can sign the peer's primary signature
     * and cover nothing else, which is that shape exactly; exempting on shape alone would let them join the
     * message as an accepted signer, which is the thing the count exists to refuse.
     *
     * A MAC is the case with nothing to compare: it names no party, so an endorsement of it cannot be held
     * against an identity and the exemption is unconditional. That is also the shape the exemption exists for,
     * since a session key proves possession of nothing and the endorsement is where an identity enters.
     *
     * An endorsement of a certificate-keyed signature is not exempt, and so falls into the count with its own
     * certificate. It then passes exactly when that certificate is the one it endorsed, which is the ordinary
     * asymmetric endorsement, and refuses when it is somebody else's.
     *
     * @param list<VerifiedOneSignature> $verifiedSignatures
     * @param list<Element>              $signatureElements
     */
    private static function endorsesOnlySecretKeyed(
        VerifiedOneSignature $verified,
        array $verifiedSignatures,
        array $signatureElements,
    ): bool {
        $endorsed = self::endorsedSignatures($verified->elements, $signatureElements);
        if ($endorsed === []) {
            // Covering no signature at all is not an endorsement: it vouches for parts of the message like any
            // other signature, so it answers to the count like any other.
            return false;
        }

        foreach ($endorsed as $index) {
            if ($verifiedSignatures[$index]->signer !== null) {
                return false;
            }
        }

        return true;
    }

    /**
     * Which of the scope's signatures a set of covered elements endorses, as positions in $signatureElements.
     * Compared by instance, so a look-alike element elsewhere in the document is not one of them.
     *
     * @param list<Element> $covered
     * @param list<Element> $signatureElements
     *
     * @return list<non-negative-int>
     */
    private static function endorsedSignatures(array $covered, array $signatureElements): array
    {
        $endorsed = [];
        foreach ($signatureElements as $index => $signature) {
            if (in_array($signature, $covered, true)) {
                $endorsed[] = $index;
            }
        }

        return $endorsed;
    }

    /**
     * Whether a signature covered one that verified, which is the shape of an endorsement and is what decides
     * whether its own coverage is reported. Narrower than the exemption above on purpose: a signature covering
     * the primary plus a part of its own choosing has that part discarded here whoever keyed it, so the
     * exemption cannot become a way to launder one.
     *
     * @param list<Element> $covered
     * @param list<Element> $signatureElements
     */
    private static function endorses(array $covered, array $signatureElements): bool
    {
        return self::signaturesAmong($covered, $signatureElements) !== [];
    }

    /**
     * The positions in $covered holding a verified signature, which is all an endorsement reports having
     * covered. Positions rather than elements, because the caller reports the id beside each one.
     *
     * @param list<Element> $covered
     * @param list<Element> $signatureElements
     *
     * @return list<non-negative-int>
     */
    private static function signaturesAmong(array $covered, array $signatureElements): array
    {
        return array_keys(array_filter(
            $covered,
            static fn (Element $element): bool => in_array($element, $signatureElements, true),
        ));
    }

    /**
     * One signature, verified whole: its algorithms allow-listed, its key resolved and held against its method,
     * every reference resolved and digested, and finally the signature value itself.
     *
     * @throws SignatureVerificationFailed
     */
    private function verifyOne(
        Document $document,
        VerificationPolicy $policy,
        Element $signature,
    ): VerifiedOneSignature {
        $signedInfo = $this->signedInfoParser->parse(
            $signature,
            $policy->externalParts?->transform,
            $this->dereferencingTransform,
        );

        $this->policyEnforcer->enforce($policy, $signedInfo);

        $verificationKey = $this->assertKeyMatchesMethod(
            $this->verificationKeyExtractor->extract($document, $signature, $policy->trustStore),
            $signedInfo->signatureMethod,
            $policy,
        );

        $resolved = $this->referenceResolver->resolve(
            $document,
            $signedInfo->referenceElements,
            $signedInfo->references,
            $signature,
            $policy->externalParts,
        );

        $this->verifyDigests($resolved);

        if (!$this->signatureValidator->validate(
            $signature,
            $verificationKey->key,
            $signedInfo->signatureMethod,
            $signedInfo->canonicalization,
            $signedInfo->canonicalizationInclusivePrefixes,
        )) {
            throw SignatureVerificationFailed::withReason('The signature value did not verify.');
        }

        // What a signature covered is what it digested, so a reference whose transform substituted the
        // element reports the substituted one. A caller asserting coverage by identity is asking about the
        // token, never about the indirection that named it.
        return new VerifiedOneSignature(
            $signature,
            array_map(
                static fn (ResolvedVerificationReference $reference): Element => $reference->digested(),
                $resolved->elements,
            ),
            array_map(
                static fn (ResolvedVerificationReference $reference): string => $reference->id,
                $resolved->elements,
            ),
            array_map(
                static fn (ResolvedExternalReference $reference): ExternalPart => $reference->part,
                $resolved->external,
            ),
            $verificationKey->signer,
        );
    }

    /**
     * The kind of key the ds:KeyInfo resolved to must be the kind the signature method needs, and this is where
     * the two are held against each other.
     *
     * An HMAC method verified with a certificate is the algorithm-confusion forgery: the "secret" would be the
     * peer's public key bytes, which anyone has. An asymmetric method verified with a secret is the mirror
     * image, and skips the trust decision entirely. Neither is a configuration mistake to be resolved in the
     * caller's favour.
     *
     * A secret has no signer: it is its own evidence, because only this exchange could have established it.
     *
     * @throws SignatureVerificationFailed
     */
    private function assertKeyMatchesMethod(
        CertificateChain|SessionKey $resolved,
        SignatureMethod $method,
        VerificationPolicy $policy,
    ): VerificationKey {
        $keyed = $method->keyKind() === SignatureKeyKind::Hmac;

        if ($resolved instanceof SessionKey) {
            return $keyed
                ? VerificationKey::ofSecret($resolved)
                : throw SignatureVerificationFailed::withReason('The signature method does not match the key.');
        }

        if ($keyed) {
            throw SignatureVerificationFailed::withReason('The signature method does not match the key.');
        }

        $signer = $this->establishTrust($resolved, $policy);
        $this->assertKeyStrongEnough($signer, $policy);

        return VerificationKey::ofSigner($signer);
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
     * Both kinds, with the same verdict on failure: which reference failed and whether it named an element or
     * an attachment are exactly the details a forgery oracle would want.
     */
    private function verifyDigests(ResolvedReferences $resolved): void
    {
        foreach ($resolved->elements as $reference) {
            if (!$this->digestVerifier->verify($reference)) {
                throw SignatureVerificationFailed::withReason('A reference digest did not match.');
            }
        }

        foreach ($resolved->external as $reference) {
            if (!$this->digestVerifier->verifyExternalPart($reference)) {
                throw SignatureVerificationFailed::withReason('A reference digest did not match.');
            }
        }
    }
}
