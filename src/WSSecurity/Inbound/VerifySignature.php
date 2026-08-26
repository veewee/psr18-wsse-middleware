<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\KeyStore\TrustedSigner;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentSignatureTransform;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\PreSharedSessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Validator\RequiredPartsValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\SecurityTokenReferenceTransform;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseKeyInfoResolver;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\External\ExternalPartVerification;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\XmlSignatureVerifier;
use Throwable;

/**
 * Enforces the signature policy over the evidence the verifier returns. The verifier reports which exact nodes
 * a trusted signer covered; this block decides whether that is enough by asserting every required part is in
 * the signed set, compared by object identity so a relocated or duplicated look-alike cannot pass as signed.
 *
 * The accepted algorithms come from the security profile as allow-lists, secure by default: a message signed
 * with an algorithm the profile does not accept is refused. Every failure cause, whether the verifier refused
 * the signature, the canonicalization could not be produced, a required part was not signed, or a required
 * element is absent, collapses to one uniform SecurityFault carrying no step-identifying detail, so the block
 * is never a forgery or validation oracle for a peer.
 *
 * A signature keyed by a symmetric secret verifies against a key this exchange established and against nothing
 * else, so a response to a request that established one needs no configuration here. A pre-shared secret is
 * the exception: no outbound direction established it, so the source holding it is handed over.
 */
final class VerifySignature implements InboundAction
{
    private ?XmlSignatureVerifier $verifier = null;
    private readonly RequiredPartsValidator $requiredParts;
    private ?PreSharedSessionKey $preSharedKey = null;

    /** @var (callable(TrustedSigner): void)|null */
    private $signerCheck = null;

    private ?ExternalParts $attachments = null;

    /**
     * A signature must cover the Body unless the caller says otherwise, so the shorter call is not the weaker
     * one. Requiring nothing would let a valid signature over a decoy the peer minted in its own header pass
     * while the Body stayed attacker-controlled.
     *
     * The Body alone, rather than everything the outbound block signs: peers commonly sign the Body and the
     * Timestamp and leave their own BinarySecurityToken unsigned, so requiring the header contents would
     * refuse conformant messages. Name the Timestamp explicitly when the peer signs it, which pairs with
     * ValidateTimestamp.
     *
     * @param list<Part>|null $signed null requires the Body; an explicit list replaces that entirely
     */
    public function __construct(
        private readonly TrustStore $trustStore,
        private readonly ?array $signed = null,
    ) {
        // The WS-Security profile references signed parts by wsu:Id, so the required-part locator resolves ids
        // through the wsu:Id convention.
        // Only the read half is handed over: nothing inbound mints, and a class that holds no minter cannot.
        $this->requiredParts = new RequiredPartsValidator(new TargetLocator(self::idLookup()));
    }

    /**
     * Registers a secret no outbound direction established, so a symmetric signature keyed by it can be
     * verified. Only a pre-shared key needs this: a wrapped or derived key was established while the request
     * was written, and the exchange already holds it.
     *
     * The secret is registered when the block runs rather than now, because the exchange it belongs to is the
     * one in flight.
     */
    public function withPreSharedKey(PreSharedSessionKey $key): self
    {
        $clone = clone $this;
        $clone->preSharedKey = $key;

        return $clone;
    }

    /**
     * Requires the message's attachments to be covered by the verified signature.
     *
     * Presence is behaviour here, as everywhere else in this package: registering parts is the requirement
     * that all of them be signed. A peer that simply omits an attachment reference is refused rather than
     * quietly accepted, because "the signature said nothing about this file" and "the file is signed" must not
     * look the same to a caller.
     *
     * Pass AttachmentParts::response() for the inbound side. Register the parts this block should insist on,
     * which for a decrypted message means running it after Inbound\Decrypt: the digest covers the plaintext.
     */
    public function withAttachments(ExternalParts $attachments): self
    {
        $clone = clone $this;
        $clone->attachments = $attachments;

        return $clone;
    }

    public function withVerifier(XmlSignatureVerifier $verifier): self
    {
        $clone = clone $this;
        $clone->verifier = $verifier;

        return $clone;
    }

    /**
     * Built per message rather than in the constructor, because the key-info resolver reads against the keys of
     * the exchange in flight and a block instance outlives every exchange it serves.
     *
     * The profile's own key-info resolver reads the WS-Security token forms; the engine on its own understands
     * only plain XML-DSig. The STR-Transform resolver is handed over for the same reason: a peer that covers its
     * token through a wsse:SecurityTokenReference needs the profile's vocabulary to be dereferenced.
     */
    private function verifier(WsseContext $context): XmlSignatureVerifier
    {
        return $this->verifier ?? Verifier::create(
            self::idLookup(),
            new WsseKeyInfoResolver(keys: $context->keys()),
            new SecurityTokenReferenceTransform(),
        );
    }

    private static function idLookup(): IdLookup
    {
        return (new WsuIdConvention())->lookup();
    }

    /**
     * Registers a check on who signed the message. Chaining to an anchor establishes that a certificate the
     * anchor vouched for signed this message, not that your peer did: every other certificate the same issuer
     * ever signed satisfies it equally. Where the anchor is a CA rather than the peer's own pinned certificate,
     * this is where an application states which identity it expected.
     *
     * The callback runs only after the signature verified and the required parts were confirmed covered, so it
     * never sees a signer from a message that failed. Throwing from it refuses the message, and the reason is
     * chained for logs only, so it cannot become an identity oracle for a peer.
     *
     * @param callable(TrustedSigner): void $check
     */
    public function onTrustedSigner(callable $check): self
    {
        $clone = clone $this;
        $clone->signerCheck = $check;

        return $clone;
    }

    /**
     * @throws SecurityFault
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        $attachments = $this->attachments;

        try {
            // A pre-shared secret is registered before anything reads a ds:KeyInfo, so the reference naming it
            // resolves. Registration is idempotent, which is what lets both inbound blocks hold one source.
            $this->preSharedKey?->resolve($context, KeyRequest::any());

            // Collected inside the try, because collecting is itself work over peer-controlled bytes: under a
            // complete coverage it canonicalizes headers a peer chose, and after Decrypt ran those headers
            // came out of that peer's ciphertext. A refusal there is an inbound failure like any other and
            // must not reach the caller as a different exception.
            //
            // Collected before the verifier runs, and the same list is used to check coverage afterwards, so
            // the parts the signature was checked against are exactly the parts the requirement is asserted
            // over.
            $registeredAttachments = $attachments?->collect();
            $policy = new VerificationPolicy(
                $this->trustStore,
                $context->profile()->crypto(),
                $attachments !== null && $registeredAttachments !== null
                    ? new ExternalPartVerification(
                        $registeredAttachments,
                        AttachmentSignatureTransform::for($attachments->coverage())->value,
                    )
                    : null,
            );

            // The signature is read out of the Security header addressed to this receiver, not searched for
            // across the envelope: a signature in another hop's header covers that hop's requirements, not
            // ours, and one planted elsewhere is not a candidate at all. A message carrying no header for us
            // is refused rather than verified against whatever else the envelope holds.
            $scope = SecurityHeader::locate($document, $context->soapVersion(), $context->profile()->actorOrRole())
                ?? throw SignatureVerificationFailed::withReason('The message carries no Security header for this receiver.');

            $verified = $this->verifier($context)->verify($document, $policy, $scope);
        } catch (SignatureVerificationFailed | CanonicalizationFailed | WsseHeaderException $exception) {
            throw SecurityFault::inboundFailure($exception);
        } catch (Throwable $foreign) {
            // The verifier is a replaceable seam, so a third-party one raises types this package never declares.
            // Letting those through would hand a peer one distinguishable outcome per implementation quirk,
            // which is the oracle this fault exists to deny; whether the cause is a bug or a deliberate type is
            // not something the code can tell apart, and the peer observes the difference either way. Nothing
            // is lost locally: the original is chained, so an operator still gets its message and trace.
            throw SecurityFault::inboundFailure($foreign);
        }

        $this->requiredParts->validate(
            $document,
            $context->soapVersion(),
            $verified->signedElements,
            $this->signed ?? [Part::body()],
            $context->profile()->actorOrRole(),
        );

        if ($registeredAttachments !== null) {
            $this->assertEveryAttachmentSigned($registeredAttachments, $verified->signedExternalParts());
        }

        $signerCheck = $this->signerCheck;
        if ($signerCheck !== null) {
            $this->assertEverySignerAccepted($verified->signers, $signerCheck);
        }
    }

    /**
     * The registered check runs against every signer the message carried, and all of them must pass.
     *
     * All rather than any: the caller is saying which identity they expected, so a second signature from some
     * other certificate their trust store happens to hold is exactly the thing they did not expect. Refusing
     * costs a message a lenient reading would have accepted; accepting would let an identity they never named
     * contribute to a message they believe they checked.
     *
     * No signers at all means every signature was keyed by a shared secret, which names no party. Refused
     * rather than skipped: a check that silently does not run is worse than none at all.
     *
     * @param list<TrustedSigner>           $signers
     * @param callable(TrustedSigner): void $check
     *
     * @throws SecurityFault
     */
    private function assertEverySignerAccepted(array $signers, callable $check): void
    {
        if ($signers === []) {
            throw SecurityFault::inboundFailure(SignatureVerificationFailed::withReason(
                'The message is signed only by a shared secret and names no signer to check.',
            ));
        }

        foreach ($signers as $signer) {
            try {
                $check($signer);
            } catch (Throwable $exception) {
                throw SecurityFault::inboundFailure($exception);
            }
        }
    }

    /**
     * Every registered part must appear in what the signature covered.
     *
     * Matched by reference rather than by object identity, unlike the element check: an external part is not a
     * node in a document anyone could swap, and the reference is what the digest was bound to. A part missing
     * from the covered set means the signature said nothing about that file, which is the case this refusal
     * exists for.
     *
     * @throws SecurityFault
     */
    private function assertEveryAttachmentSigned(
        ExternalPartList $registeredAttachments,
        ExternalPartList $covered,
    ): void {
        foreach ($registeredAttachments as $part) {
            if ($covered->byReference($part->reference) === null) {
                throw SecurityFault::inboundFailure(SignatureVerificationFailed::withReason(
                    'A registered attachment is not covered by the signature.',
                ));
            }
        }
    }
}
