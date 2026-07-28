<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Validator\RequiredPartsValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuIdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\Verifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\XmlSignatureVerifier;

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
 */
final class VerifySignature implements InboundAction
{
    private XmlSignatureVerifier $verifier;
    private readonly RequiredPartsValidator $requiredParts;

    /**
     * @param list<Part> $signed
     */
    public function __construct(
        private readonly TrustStore $trustStore,
        private readonly array $signed = [],
    ) {
        // The WS-Security profile references signed parts by wsu:Id, so both the verifier and the required-part
        // locator resolve ids through the wsu:Id convention.
        $lookup = new WsuIdLookup();
        $this->verifier = Verifier::create($lookup);
        $this->requiredParts = new RequiredPartsValidator(new TargetLocator($lookup));
    }

    public function withVerifier(XmlSignatureVerifier $verifier): self
    {
        $clone = clone $this;
        $clone->verifier = $verifier;

        return $clone;
    }

    /**
     * @throws SecurityFault
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();
        $policy = new VerificationPolicy($this->trustStore, $context->profile()->crypto());

        try {
            // The signature is read out of the Security header addressed to this receiver, not searched for
            // across the envelope: a signature in another hop's header covers that hop's requirements, not
            // ours, and one planted elsewhere is not a candidate at all. A message carrying no header for us
            // is refused rather than verified against whatever else the envelope holds.
            $scope = SecurityHeader::locate($document, $context->soapVersion())
                ?? throw SignatureVerificationFailed::withReason('The message carries no Security header for this receiver.');

            $verified = $this->verifier->verify($document, $policy, $scope);
        } catch (SignatureVerificationFailed | CanonicalizationFailed | WsseHeaderException $exception) {
            throw SecurityFault::inboundFailure($exception);
        }

        $this->requiredParts->validate($document, $context->soapVersion(), $verified->signedElements, $this->signed);
    }
}
