<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\CanonicalizationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Inbound\Internal\Validator\RequiredPartsValidator;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SecurityProfile;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\DefaultEngine;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\PartLocator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\XmlSignatureVerifier;

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
        $this->verifier = DefaultEngine::verifier();
        $this->requiredParts = new RequiredPartsValidator(new PartLocator());
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
        $policy = $this->buildPolicy($context->profile());

        try {
            $verified = $this->verifier->verify($document, $policy);
        } catch (SignatureVerificationFailed | CanonicalizationFailed $exception) {
            throw SecurityFault::inboundFailure($exception);
        }

        $this->requiredParts->validate($document, $verified->signedElements, $this->signed);
    }

    private function buildPolicy(SecurityProfile $profile): VerificationPolicy
    {
        return new VerificationPolicy(
            trustStore: $this->trustStore,
            acceptedSignatureMethods: $this->acceptedSignatureMethods($profile),
            acceptedDigestMethods: $this->acceptedDigestMethods($profile),
            acceptedCanonicalizations: $this->acceptedCanonicalizations($profile),
        );
    }

    /**
     * @return non-empty-list<SignatureMethod>
     */
    private function acceptedSignatureMethods(SecurityProfile $profile): array
    {
        $accepted = array_values(array_filter(
            SignatureMethod::cases(),
            $profile->acceptsSignatureMethod(...),
        ));
        if ($accepted === []) {
            throw new InvalidArgumentException('The security profile accepts no signature methods.');
        }

        return $accepted;
    }

    /**
     * @return non-empty-list<DigestMethod>
     */
    private function acceptedDigestMethods(SecurityProfile $profile): array
    {
        $accepted = array_values(array_filter(
            DigestMethod::cases(),
            $profile->acceptsDigestMethod(...),
        ));
        if ($accepted === []) {
            throw new InvalidArgumentException('The security profile accepts no digest methods.');
        }

        return $accepted;
    }

    /**
     * @return non-empty-list<SignatureCanonicalization>
     */
    private function acceptedCanonicalizations(SecurityProfile $profile): array
    {
        $accepted = array_values(array_filter(
            SignatureCanonicalization::cases(),
            $profile->acceptsCanonicalization(...),
        ));
        if ($accepted === []) {
            throw new InvalidArgumentException('The security profile accepts no canonicalizations.');
        }

        return $accepted;
    }
}
