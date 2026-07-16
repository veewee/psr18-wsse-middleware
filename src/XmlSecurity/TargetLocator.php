<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\WsuId;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\document_element;
use function VeeWee\Xml\Dom\Locator\Element\locate_by_namespaced_tag_name;

/**
 * Translates a Target descriptor into the single DOM Element it addresses: an element by qualified name, or an
 * element by its id. The result is always the element that will be canonicalized or encrypted, so the locator
 * never mints ids (that is the collector's step after locating). SOAP shortcuts (Body, Timestamp) are resolved
 * to a Target by the WS-Security profile before reaching here.
 */
final class TargetLocator
{
    /**
     * @throws IdReferenceException when the Target's element is absent or ambiguous
     */
    public function locate(Document $document, Target $target): Element
    {
        return match ($target->kind()) {
            TargetKind::Element => $this->locateElement($document, $target),
            TargetKind::Id => WsuId::resolve($document, (string) $target->id()),
        };
    }

    /**
     * @throws IdReferenceException
     */
    private function locateElement(Document $document, Target $target): Element
    {
        $namespace = (string) $target->namespace();
        $localName = (string) $target->localName();

        $matches = locate_by_namespaced_tag_name($document->locate(document_element()), $namespace, $localName);

        return match ($matches->count()) {
            0 => throw IdReferenceException::notFound($namespace.':'.$localName),
            1 => $matches->expectSingle(),
            default => throw IdReferenceException::ambiguous($namespace.':'.$localName),
        };
    }
}
