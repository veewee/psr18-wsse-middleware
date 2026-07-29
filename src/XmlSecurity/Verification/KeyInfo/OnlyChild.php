<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\XmlNamespace;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\SignatureVerificationFailed;

/**
 * Reads the at-most-one child of a ds:KeyInfo shape, refusing a second one as ambiguous rather than taking the
 * first. Shared by every resolver so the rule cannot differ between the shapes they read: a duplicated element is
 * how a wrapping payload puts a reference the verifier reads beside the one it checked.
 */
final class OnlyChild
{
    /**
     * @throws SignatureVerificationFailed when more than one such child is present
     */
    public static function named(Element $parent, XmlNamespace $namespace, string $localName): ?Element
    {
        $matches = ChildElements::named($parent, $namespace, $localName);
        if (count($matches) > 1) {
            throw SignatureVerificationFailed::withReason(
                sprintf('%s must appear at most once in its parent.', $localName),
            );
        }

        return $matches[0] ?? null;
    }
}
