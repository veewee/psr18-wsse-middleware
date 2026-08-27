<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use function VeeWee\Xml\Dom\Locator\Element\children;

/**
 * Expands a dynamic Part (securityHeaderContents/soapHeaders/primarySignature) to the live elements it
 * addresses, or returns null for a static Part. Pure enumeration shared by both directions: the outbound
 * Signature block mints a wsu:Id on each member and signs it, the inbound RequiredPartsValidator checks each
 * member was signed. The ds:Signature is excluded from securityHeaderContents in both directions. A signature is
 * never one of the parts it covers, and outbound it does not yet exist when the parts are resolved.
 *
 * primarySignature is the one dynamic part that refuses rather than expanding to what it finds. Nothing to
 * endorse and two things to endorse are both configurations that would otherwise pass while protecting nothing
 * or protecting the wrong element.
 */
final class DynamicPartMembers
{
    /**
     * The Security header is required, not nullable: a dynamic part that cannot be tied to a header has no
     * members, and silently treating that as "nothing to require" is how a coverage check passes vacuously.
     * A caller that cannot locate the header refuses the part instead of asking for its members.
     *
     * @return list<Element>|null null when the Part is static (Body/Element/Id)
     *
     * @throws WsseHeaderException when primarySignature finds no signature to endorse, or more than one
     */
    public static function forPart(Part $part, Element $securityHeader): ?array
    {
        return match ($part->kind()) {
            PartKind::SecurityHeaderContents => self::securityHeaderChildren($securityHeader),
            PartKind::SoapHeaders => self::soapHeaderBlocks($securityHeader),
            PartKind::PrimarySignature => [self::primarySignature($securityHeader)],
            default => null,
        };
    }

    /**
     * The one ds:Signature in the header.
     *
     * None is refused rather than expanded to nothing: an endorsing block placed before the block it endorses
     * would otherwise sign nothing while the caller believes the primary signature is covered. Two are refused
     * rather than resolved by position: which of them a reader treats as primary is not something document
     * order decides, and endorsing the wrong one endorses nothing.
     *
     * @throws WsseHeaderException
     */
    private static function primarySignature(Element $securityHeader): Element
    {
        $signatures = children($securityHeader)
            ->filter(static fn (Element $child): bool => self::isSignature($child))
            ->map(static fn (Element $child): Element => $child);

        return match (count($signatures)) {
            1 => $signatures[0],
            0 => throw WsseHeaderException::noPrimarySignature(),
            default => throw WsseHeaderException::ambiguousPrimarySignature(),
        };
    }

    /**
     * @return list<Element>
     */
    private static function securityHeaderChildren(Element $securityHeader): array
    {
        return children($securityHeader)
            ->filter(static fn (Element $child): bool => !self::isSignature($child))
            ->map(static fn (Element $child): Element => $child);
    }

    /**
     * @return list<Element>
     */
    private static function soapHeaderBlocks(Element $securityHeader): array
    {
        // On a received message the located Security header can sit anywhere (a relocated header may even be
        // the document root); a missing element parent means there are no sibling SOAP headers to require, so
        // this stays vacuously satisfied rather than crashing past the uniform SecurityFault the caller expects.
        $soapHeader = $securityHeader->parentElement;
        if (!$soapHeader instanceof Element) {
            return [];
        }

        return children($soapHeader)
            ->filter(static fn (Element $header): bool => $header !== $securityHeader)
            ->map(static fn (Element $header): Element => $header);
    }

    private static function isSignature(Element $element): bool
    {
        return ElementName::matches($element, Namespaces::Ds, 'Signature');
    }
}
