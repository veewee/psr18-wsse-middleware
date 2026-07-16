<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\ResolvedReference;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves each Target in a signing request to the DOM element it describes, reusing the element's existing
 * wsu:Id or minting a fresh id via the injected IdMinter when it carries none. Returns one ResolvedReference
 * per distinct element, in first-seen
 * order: when several Targets resolve to the same element instance, only the first is kept so the signature
 * carries one ds:Reference per signed element.
 *
 * Callers must pass the same Document the signing flow operates on; the minted ids are stamped onto its
 * elements in place.
 */
final class ReferenceCollector
{
    public function __construct(
        private IdMinter $minter,
        private TargetLocator $locator,
    ) {
    }

    /**
     * @param non-empty-list<Target> $targets
     *
     * @return non-empty-list<ResolvedReference> one per distinct resolved element (deduplicated)
     *
     * @throws IdReferenceException when a Target cannot be located
     */
    public function collect(Document $document, array $targets): array
    {
        $references = [];
        $seen = [];

        foreach ($targets as $target) {
            $element = $this->locator->locate($document, $target);

            // Deduplicate by element identity: a second Target pointing at the same node adds no reference.
            if (in_array($element, $seen, true)) {
                continue;
            }
            $seen[] = $element;

            $references[] = new ResolvedReference($element, $this->wsuId($document, $element));
        }

        // At least one Target is guaranteed, and the first is always kept, so the list is non-empty.
        assert($references !== []);

        return $references;
    }

    /**
     * @return non-empty-string
     */
    private function wsuId(Document $document, Element $element): string
    {
        $existing = $element->getAttributeNS(Namespaces::Wsu->value, 'Id');
        if ($existing !== null && $existing !== '') {
            return $existing;
        }

        return $this->minter->mint($element, $document);
    }
}
