<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SignatureVerificationFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath;
use VeeWee\Xml\Dom\Document;

/**
 * Locates the single ds:Signature inside the wsse:Security header. Exactly one is required, so a second
 * injected ds:Signature cannot offer the verifier an alternative to validate. A violation surfaces as one
 * SignatureVerificationFailed with a non-identifying message.
 */
final class SignatureLocator
{
    /**
     * @throws SignatureVerificationFailed
     */
    public function locate(Document $document): Element
    {
        $signatures = $document
            ->xpath(new Xpath($document))
            ->query(
                '//'.Namespaces::Wsse->qualify('Security').'/'.Namespaces::Ds->qualify('Signature'),
            )
            ->expectAllOfType(Element::class);

        if ($signatures->count() !== 1) {
            throw SignatureVerificationFailed::withReason(
                'Exactly one ds:Signature is required in the Security header.',
            );
        }

        return $signatures->expectSingle();
    }
}
