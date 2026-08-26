<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\XmlSignatureVerifier;
use VeeWee\Xml\Dom\Document;

/**
 * Captures the document, policy and scope the block hands to the verifier and returns a fixed result so the
 * unit-level tests can assert the wiring, the policy contents and which region was verified without running the
 * real crypto path.
 */
final class RecordingVerifier implements XmlSignatureVerifier
{
    private ?Document $document = null;
    private ?VerificationPolicy $policy = null;
    private ?Element $scope = null;

    public function __construct(private readonly VerifiedSignature $result)
    {
    }

    public function verify(Document $document, VerificationPolicy $policy, Element $scope): VerifiedSignature
    {
        $this->document = $document;
        $this->policy = $policy;
        $this->scope = $scope;

        return $this->result;
    }

    public function lastDocument(): ?Document
    {
        return $this->document;
    }

    public function lastPolicy(): ?VerificationPolicy
    {
        return $this->policy;
    }

    public function lastScope(): ?Element
    {
        return $this->scope;
    }
}
