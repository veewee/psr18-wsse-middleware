<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;

/**
 * Locates the single ds:Signature the caller's scope carries. Exactly one direct child is required, so a
 * second injected ds:Signature cannot offer the verifier an alternative to validate, and one wrapped deeper
 * in the scope is not mistaken for the scope's own. A violation surfaces as one SignatureVerificationFailed
 * with a non-identifying message.
 *
 * The scope is the caller's, not this class's business: the engine carries no notion of which region of a
 * message belongs to this receiver. The WS-Security profile resolves the Security header addressed to the
 * ultimate receiver and passes it, so a signature in another hop's header — or planted elsewhere in the
 * envelope entirely — is never a candidate.
 */
final class SignatureLocator
{
    /**
     * @throws SignatureVerificationFailed
     */
    public function locate(Element $scope): Element
    {
        $signatures = ChildElements::named($scope, Namespaces::Ds, 'Signature');

        if (count($signatures) !== 1) {
            throw SignatureVerificationFailed::withReason(
                'Exactly one ds:Signature is required in the scope being verified.',
            );
        }

        return $signatures[0];
    }
}
