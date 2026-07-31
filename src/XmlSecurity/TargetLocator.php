<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use LogicException;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
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
    private readonly IdLookup $idLookup;

    public function __construct(?IdLookup $idLookup = null)
    {
        // Defaulted in the body rather than in the signature: the engine's default now comes from a convention,
        // and a static call is not a legal default parameter value.
        $this->idLookup = $idLookup ?? AttributeIdConvention::xmlId()->lookup();
    }

    /**
     * @throws IdReferenceException when the Target's element is absent or ambiguous
     */
    public function locate(Document $document, Target $target): Element
    {
        return match ($target->kind()) {
            TargetKind::Element => $this->locateElement($document, $target),
            TargetKind::Id => $this->idLookup->lookup($document, $this->requireId($target)),
            TargetKind::Path => $this->locatePath($document, $target),
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
     * Walks the path one step at a time, requiring exactly one match among the direct children at each. Both an
     * absent and a duplicated step are refused, so no step is ever resolved by picking a candidate, and a
     * descendant never satisfies a step that names a child.
     *
     * @throws IdReferenceException when a step is absent, duplicated, or names a different document element
     */
    private function locatePath(Document $document, Target $target): Element
    {
        $steps = $target->steps();
        $root = $steps[0] ?? throw new LogicException('A Target of kind Path carries no steps.');

        $element = $document->locate(document_element());
        if (!$root->matches($element)) {
            throw IdReferenceException::notFound($root->toString());
        }

        foreach (array_slice($steps, 1) as $step) {
            $element = UniqueMatch::require(ChildElements::matching($element, $step), $step->toString());
        }

        return $element;
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
