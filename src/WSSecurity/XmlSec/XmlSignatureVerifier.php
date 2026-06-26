<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec;

use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request\VerificationPolicy;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Result\VerifiedSignature;
use VeeWee\Xml\Dom\Document;

/**
 * Verifies a ds:Signature. Returns the evidence (which exact nodes were signed and which trusted signer
 * produced it) rather than a bare boolean, so the caller can assert coverage by identity. The bare-bool
 * return is what the XML Signature Wrapping CVEs exploited.
 */
interface XmlSignatureVerifier
{
    public function verify(Document $document, VerificationPolicy $policy): VerifiedSignature;
}
