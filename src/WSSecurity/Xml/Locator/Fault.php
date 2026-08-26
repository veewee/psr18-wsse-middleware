<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\ReportedFault;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Query;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\Element\children;

/**
 * Finds the soap:Fault a response reported, and reads its code and reason.
 *
 * Deliberately smaller than php-soap/encoding's fault model, which types both SOAP versions properly and
 * carries the detail element too. That package is not a dependency here, and taking one on for a log line
 * would be a poor trade; its richer fault is also already reached on the path that matters, since a response
 * whose inbound checks pass goes on to the encoder and surfaces there as a SoapFaultException. This reads the
 * two fields that fit in one log line, for the one case that never reaches the encoder at all.
 *
 * The lookup is anchored at soap:Envelope/soap:Body rather than searching the document, so a fault-shaped
 * element planted in the header is not mistaken for the response's own fault. A body carrying more than one
 * is reported as none: two faults leave no single answer, and picking one is a verdict the peer steers.
 *
 * Nothing here decides anything about security. The result exists only to tell an operator what the peer said
 * about a response that failed its inbound checks, and the two SOAP versions spell that out differently: 1.1
 * uses unqualified faultcode and faultstring children, 1.2 uses soap:Code/soap:Value and soap:Reason/soap:Text.
 * Both halves are optional in either schema, and a fault stating neither is still the reason the response
 * failed, so it is reported with whatever it carries.
 */
final class Fault
{
    public function locate(Document $document, SoapVersion $soapVersion): ?ReportedFault
    {
        $faults = Query::elements($document, '/soap:Envelope/soap:Body/soap:Fault');
        if ($faults->count() !== 1) {
            return null;
        }

        $fault = $faults->expectSingle();

        return match ($soapVersion) {
            SoapVersion::Soap11 => ReportedFault::fromPeer(
                $this->unqualifiedChildText($fault, 'faultcode'),
                $this->unqualifiedChildText($fault, 'faultstring'),
            ),
            SoapVersion::Soap12 => ReportedFault::fromPeer(
                $this->nestedChildText($fault, $soapVersion, 'Code', 'Value'),
                $this->nestedChildText($fault, $soapVersion, 'Reason', 'Text'),
            ),
        };
    }

    /**
     * A SOAP 1.1 fault's own children are in no namespace, which is what the schema says and therefore what a
     * conformant peer sends. A namespaced look-alike is not read in their place.
     */
    private function unqualifiedChildText(Element $fault, string $localName): string
    {
        $matches = children($fault)
            ->filter(static fn (Element $child): bool =>
                $child->localName === $localName && $child->namespaceURI === null)
            ->map(static fn (Element $child): Element => $child);

        return count($matches) === 1 ? ElementText::trimmed($matches[0]) : '';
    }

    /**
     * A SOAP 1.2 fault states each half one level down, in the envelope namespace. A duplicate at either level
     * reads as absent, the same rule the security-relevant readers apply, so an injected sibling cannot decide
     * which text is quoted.
     */
    private function nestedChildText(
        Element $fault,
        SoapVersion $soapVersion,
        string $outerName,
        string $innerName,
    ): string {
        $outer = $this->envelopeChild($fault, $soapVersion, $outerName);
        if ($outer === null) {
            return '';
        }

        $inner = $this->envelopeChild($outer, $soapVersion, $innerName);

        return $inner === null ? '' : ElementText::trimmed($inner);
    }

    private function envelopeChild(Element $parent, SoapVersion $soapVersion, string $localName): ?Element
    {
        $namespace = $soapVersion->envelopeNamespace();
        $matches = children($parent)
            ->filter(static fn (Element $child): bool =>
                $child->localName === $localName && $child->namespaceURI === $namespace)
            ->map(static fn (Element $child): Element => $child);

        return count($matches) === 1 ? $matches[0] : null;
    }
}
