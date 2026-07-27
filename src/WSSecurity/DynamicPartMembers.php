<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\ElementName;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use VeeWee\Xml\Dom\Document;

/**
 * Expands a dynamic Part (securityHeaderContents/soapHeaders) to the live elements it addresses, or returns
 * null for a static Part. Pure enumeration shared by both directions: the outbound Signature block mints a
 * wsu:Id on each member and signs it, the inbound RequiredPartsValidator checks each member was signed. The
 * ds:Signature is excluded from securityHeaderContents in both directions — a signature is never one of the
 * parts it covers, and outbound it does not yet exist when the parts are resolved.
 */
final class DynamicPartMembers
{
    /**
     * @return list<Element>|null null when the Part is static (Body/Element/Id)
     */
    public static function forPart(Part $part, Document $document, ?Element $securityHeader): ?array
    {
        return match ($part->kind()) {
            PartKind::SecurityHeaderContents => self::securityHeaderChildren($document, $securityHeader),
            PartKind::SoapHeaders => self::soapHeaderBlocks($document, $securityHeader),
            default => null,
        };
    }

    /**
     * @return list<Element>
     */
    private static function securityHeaderChildren(Document $document, ?Element $securityHeader): array
    {
        if ($securityHeader === null) {
            return [];
        }

        return array_values(array_filter(
            self::childElements($document, $securityHeader),
            static fn (Element $child): bool => !self::isSignature($child),
        ));
    }

    /**
     * @return list<Element>
     */
    private static function soapHeaderBlocks(Document $document, ?Element $securityHeader): array
    {
        if ($securityHeader === null) {
            return [];
        }

        // On a received message the located Security header can sit anywhere (a relocated header may even be
        // the document root); a missing element parent means there are no sibling SOAP headers to require, so
        // this stays vacuously satisfied rather than crashing past the uniform SecurityFault the caller expects.
        $soapHeader = $securityHeader->parentElement;
        if (!$soapHeader instanceof Element) {
            return [];
        }

        return array_values(array_filter(
            self::childElements($document, $soapHeader),
            static fn (Element $header): bool => $header !== $securityHeader,
        ));
    }

    private static function isSignature(Element $element): bool
    {
        return ElementName::matches($element, Namespaces::Ds, 'Signature');
    }

    /**
     * @return list<Element>
     */
    private static function childElements(Document $document, Element $element): array
    {
        return Query::elements($document, 'child::*', $element)
            ->map(static fn (Element $child): Element => $child);
    }
}
