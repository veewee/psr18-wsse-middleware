<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use VeeWee\Xml\Dom\Document;

/**
 * Expresses how the signing or recipient key is referenced inside ds:KeyInfo / xenc:EncryptedKey (BST
 * direct reference, X509 SKI, IssuerSerial, Thumbprint, ...). The concrete strategies are ported onto the new
 * DOM in C2, which also finalises this signature (see DEFERRED.md).
 */
interface KeyIdentifier
{
    /**
     * Builds the ds:KeyInfo content (typically a wsse:SecurityTokenReference) and returns the element to
     * attach, telling the recipient which key verifies or decrypts.
     */
    public function apply(Document $document, Certificate $certificate): Element;
}
