<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Inbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerificationPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\XmlSignatureVerifier;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Throws a fixed exception on verify so the tests can exercise the fault-mapping arms of the block.
 */
final class ThrowingVerifier implements XmlSignatureVerifier
{
    public function __construct(private readonly Throwable $failure)
    {
    }

    public function verify(Document $document, VerificationPolicy $policy, Element $scope): VerifiedSignature
    {
        throw $this->failure;
    }
}
