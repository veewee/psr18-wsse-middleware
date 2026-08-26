<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use VeeWee\Xml\Dom\Document;

/**
 * Expresses how the signing or recipient key is referenced inside ds:KeyInfo / xenc:EncryptedKey (BST
 * direct reference, X509 SKI, IssuerSerial, Thumbprint, an EncryptedKeySHA1, ...).
 *
 * A strategy takes whatever it references at construction. A symmetric reference has no certificate to be
 * handed one, and every caller of a certificate-based strategy already holds the certificate at the point it
 * constructs the strategy, so the reference is a value that knows its own subject.
 */
interface KeyIdentifier
{
    /**
     * Builds the ds:KeyInfo content (typically a wsse:SecurityTokenReference) and returns the element to
     * attach, telling the recipient which key verifies or decrypts.
     */
    public function apply(Document $document): Element;
}
