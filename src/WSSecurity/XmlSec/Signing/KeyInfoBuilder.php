<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Signing;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;
use VeeWee\Xml\Dom\Document;

/**
 * Produces the ds:KeyInfo element that tells the recipient which key verifies the signature, by delegating to
 * the request's KeyIdentifier strategy. The certificate is the advertised signing certificate carried on the
 * request, an input distinct from the private signing key.
 *
 * Pure: it never touches the Security header. Embedding a wsse:BinarySecurityToken for the direct-reference
 * case is the outbound caller's responsibility, performed before the signing flow runs.
 */
final class KeyInfoBuilder
{
    public function build(Document $document, KeyIdentifier $keyIdentifier, Certificate $certificate): Element
    {
        return $keyIdentifier->apply($document, $certificate);
    }
}
