<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Manipulator\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\PartLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\ResolvedReference;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves each Part in a signing request to the DOM element it describes, minting a wsu:Id on the element
 * when it does not already carry one. Returns one ResolvedReference per distinct element, in first-seen
 * order: when several Parts resolve to the same element instance, only the first is kept so the signature
 * carries one ds:Reference per signed element.
 *
 * Callers must pass the same Document the signing flow operates on; the minted ids are stamped onto its
 * elements in place.
 */
final class ReferenceCollector
{
    public function __construct(
        private WsuIdMinter $minter,
        private PartLocator $locator,
    ) {
    }

    /**
     * @param non-empty-list<Part> $parts
     *
     * @return non-empty-list<ResolvedReference> one per distinct resolved element (deduplicated)
     *
     * @throws IdReferenceException when a Part cannot be located
     */
    public function collect(Document $document, array $parts): array
    {
        $references = [];
        $seen = [];

        foreach ($parts as $part) {
            $element = $this->locator->locate($document, $part);

            // Deduplicate by element identity: a second Part pointing at the same node adds no reference.
            if (in_array($element, $seen, true)) {
                continue;
            }
            $seen[] = $element;

            $references[] = new ResolvedReference($element, $this->wsuId($document, $element));
        }

        // At least one Part is guaranteed, and the first is always kept, so the list is non-empty.
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
