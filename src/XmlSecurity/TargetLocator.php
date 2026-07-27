<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use LogicException;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\UniqueMatch;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\document_element;
use function VeeWee\Xml\Dom\Locator\Element\locate_by_namespaced_tag_name;

/**
 * Translates a Target descriptor into the single DOM Element it addresses: an element by qualified name, or an
 * element by its id. The result is always the element that will be canonicalized or encrypted, so the locator
 * never mints ids (that is the collector's step after locating). By-id resolution goes through the injected
 * IdLookup, so the engine carries no id convention of its own. SOAP shortcuts (Body, Timestamp) are resolved
 * to a Target by the WS-Security profile before reaching here.
 */
final class TargetLocator
{
    public function __construct(
        private IdLookup $idLookup = new XmlIdLookup(),
    ) {
    }

    /**
     * @throws IdReferenceException when the Target's element is absent or ambiguous
     */
    public function locate(Document $document, Target $target): Element
    {
        return match ($target->kind()) {
            TargetKind::Element => $this->locateElement($document, $target),
            TargetKind::Id => $this->idLookup->lookup($document, $this->requireId($target)),
        };
    }

    /**
     * The id of a TargetKind::Id target. The storage is nullable because it is shared across every kind, so
     * this restates which field the Id factory populated.
     *
     * @return non-empty-string
     */
    private function requireId(Target $target): string
    {
        return $target->id() ?? throw new LogicException('A Target of kind Id carries no id.');
    }

    /**
     * @throws IdReferenceException
     */
    private function locateElement(Document $document, Target $target): Element
    {
        $namespace = (string) $target->namespace();
        $localName = (string) $target->localName();

        $matches = locate_by_namespaced_tag_name($document->locate(document_element()), $namespace, $localName);

        return UniqueMatch::require(
            $matches->map(static fn (Element $element): Element => $element),
            $namespace.':'.$localName,
        );
    }
}
