<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\PartKind;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseXpath;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdResolver;
use Soap\Xml\Locator\SoapBodyLocator;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\document_element;
use function VeeWee\Xml\Dom\Locator\Element\locate_by_namespaced_tag_name;

/**
 * Translates a Part descriptor into the single DOM Element it addresses. One branch per PartKind; the result
 * is always the element that will be canonicalized, so the locator never mints ids (that is the collector's
 * step after locating).
 */
final class PartLocator
{
    /**
     * @throws IdReferenceException when the Part's target element is absent or ambiguous
     */
    public function locate(Document $document, Part $part): Element
    {
        return match ($part->kind()) {
            PartKind::Body => $this->locateBody($document),
            PartKind::Timestamp => $this->locateTimestamp($document),
            PartKind::Element => $this->locateElement($document, $part),
            PartKind::Id => WsuIdResolver::resolve($document, (string) $part->id()),
        };
    }

    /**
     * @throws IdReferenceException
     */
    private function locateBody(Document $document): Element
    {
        $body = $document->locate(new SoapBodyLocator());
        if ($body === null) {
            throw IdReferenceException::notFound('soap:Body');
        }

        return $body;
    }

    /**
     * @throws IdReferenceException
     */
    private function locateTimestamp(Document $document): Element
    {
        $timestamp = $document
            ->xpath(new WsseXpath($document))
            ->query('//'.WsseNamespace::Wsu->qualify('Timestamp'))
            ->expectAllOfType(Element::class)
            ->first();

        if ($timestamp === null) {
            throw IdReferenceException::notFound('wsu:Timestamp');
        }

        return $timestamp;
    }

    /**
     * @throws IdReferenceException
     */
    private function locateElement(Document $document, Part $part): Element
    {
        $namespace = (string) $part->namespace();
        $localName = (string) $part->localName();

        $matches = locate_by_namespaced_tag_name($document->locate(document_element()), $namespace, $localName);

        return match ($matches->count()) {
            0 => throw IdReferenceException::notFound($namespace.':'.$localName),
            1 => $matches->expectSingle(),
            default => throw IdReferenceException::ambiguous($namespace.':'.$localName),
        };
    }
}
