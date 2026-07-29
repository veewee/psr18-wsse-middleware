<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;
use VeeWee\Xml\Dom\Document;

/**
 * Verifies a ds:Signature. Returns the evidence (which exact nodes were signed and which trusted signer
 * produced it) rather than a bare boolean, so the caller can assert coverage by identity. The bare-bool
 * return is what the XML Signature Wrapping CVEs exploited.
 *
 * The scope is the element whose signature is being verified: the caller's own region of the message. The
 * engine has no way to tell which region that is, so it is an explicit input rather than something searched
 * for, mirroring the container a signing request names.
 */
interface XmlSignatureVerifier
{
    public function verify(Document $document, VerificationPolicy $policy, Element $scope): VerifiedSignature;
}
