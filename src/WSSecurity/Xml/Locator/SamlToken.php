<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\SamlVersion;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\QualifiedName;

/**
 * Finds the saml:Assertion a wsse:Security header carries and reports its id and version, so a signature can
 * reference the assertion a sibling block imported without either block holding on to per-message state.
 *
 * The header to search is handed in rather than looked up here, for the reason the binary token locator gives:
 * the caller already holds the header it is writing into, and searching only that header keeps an assertion
 * sitting anywhere else in the envelope from being treated as one of ours.
 *
 * Both SAML namespaces are searched together and more than one match is refused, whichever versions they are.
 * A message carrying two assertions has no single answer to "which key does this signature claim", and picking
 * one would let a second assertion decide what the reference means.
 */
final class SamlToken
{
    /**
     * @throws WsseHeaderException when the header carries no assertion, or more than one
     */
    public function locate(Element $securityHeader): LocatedSamlAssertion
    {
        $found = [];

        foreach (SamlVersion::cases() as $version) {
            foreach (ChildElements::matching($securityHeader, new QualifiedName($version->value, 'Assertion')) as $assertion) {
                $found[] = [$assertion, $version];
            }
        }

        if (count($found) !== 1) {
            throw WsseHeaderException::samlAssertionNotLocatable();
        }

        [$assertion, $version] = $found[0];

        // The version decides which attribute carries the id, and it was derived from the element's own
        // namespace rather than restated, so a reference cannot describe a different version than the assertion
        // it points at.
        $id = $assertion->getAttribute($version->idAttribute());
        if ($id === null || $id === '') {
            throw WsseHeaderException::samlAssertionIdMissing($version->idAttribute());
        }

        return new LocatedSamlAssertion($id, $version);
    }
}
