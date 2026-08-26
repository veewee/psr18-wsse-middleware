<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\SignedInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;

/**
 * Locates the ds:Signature elements the caller's scope carries, as its direct children.
 *
 * Direct children only, so one wrapped deeper in the scope is never mistaken for the scope's own. That is the
 * XML Signature Wrapping defense here, and it does not depend on how many there are.
 *
 * Several are allowed, because a message may legitimately carry more than one: an endorsing supporting token is
 * a second signature over the first, and the profile permits it. What keeps that safe is not a count but the
 * rule the orchestrator applies to the result, that **every** signature found must verify against a key it
 * accepts. An injected extra one therefore refuses the message rather than offering an alternative to validate.
 *
 * The number is bounded all the same. Each signature costs a canonicalization, a digest per reference and a
 * crypto operation, so an unbounded count is a denial-of-service lever rather than a richer message.
 *
 * The scope is the caller's, not this class's business: the engine carries no notion of which region of a
 * message belongs to this receiver. The WS-Security profile resolves the Security header addressed to the
 * ultimate receiver and passes it, so a signature in another hop's header: or planted elsewhere in the
 * envelope entirely: is never a candidate.
 */
final class SignatureLocator
{
    /**
     * The upper bound on ds:Signature elements one scope may carry. A conservative ceiling far above any
     * legitimate message: two is the endorsing shape, and nothing this package has met emits more than three.
     * Follows the bound the decryptor puts on a reference list.
     */
    public const int MAX_SIGNATURES = 8;

    /**
     * @return non-empty-list<Element> in document order, which is the order they are verified in
     *
     * @throws SignatureVerificationFailed
     */
    public function locate(Element $scope): array
    {
        $signatures = ChildElements::named($scope, Namespaces::Ds, 'Signature');

        if ($signatures === []) {
            throw SignatureVerificationFailed::withReason('The scope being verified carries no ds:Signature.');
        }

        if (count($signatures) > self::MAX_SIGNATURES) {
            throw SignatureVerificationFailed::withReason('The scope being verified carries too many signatures.');
        }

        return $signatures;
    }
}
