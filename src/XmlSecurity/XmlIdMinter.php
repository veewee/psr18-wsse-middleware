<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use Dom\XPath;
use Symfony\Component\Uid\Uuid;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\namespaced_attribute;

/**
 * The engine's default IdMinter: mints an id that is unique within a document and stamps it as the
 * W3C-standard xml:id, so a standalone caller can sign or encrypt with zero configuration. A v4 UUID gives
 * uniqueness without any shared state; the "id-" prefix makes the value a valid XML NCName (which cannot start
 * with a digit).
 *
 * Parallel to the profile-specific minter a WS-Security profile injects, but on the plain W3C xml:id.
 */
final class XmlIdMinter implements IdMinter
{
    private const XML_NS = 'http://www.w3.org/XML/1998/namespace';

    /**
     * @return non-empty-string
     */
    public function mint(Element $node, Document $document): string
    {
        $existing = $this->existingId($node);
        if ($existing !== null) {
            return $existing;
        }

        $id = $this->uniqueId($document);
        namespaced_attribute(self::XML_NS, 'xml:id', $id)($node);

        return $id;
    }

    /**
     * @return non-empty-string|null
     */
    private function existingId(Element $node): ?string
    {
        // The new Dom\ API returns null for an absent attribute (unlike the old DOM "" sentinel).
        $existing = $node->getAttributeNS(self::XML_NS, 'id');

        return $existing === null || $existing === '' ? null : $existing;
    }

    /**
     * @return non-empty-string
     */
    private function uniqueId(Document $document): string
    {
        // A v4 UUID collision is effectively unreachable; the guard guarantees the value is free (and not a
        // pre-existing duplicate) before stamping.
        do {
            $id = 'id-'.Uuid::v4()->toRfc4122();
        } while (!$this->isFree($document, $id));

        return $id;
    }

    private function isFree(Document $document, string $id): bool
    {
        // The xml prefix is bound to the XML namespace for every XPath, so no namespace registration is needed.
        $xpath = new XPath($document->toUnsafeDocument());

        return $xpath->query('//*[@xml:id='.XPath::quote($id).']')->length === 0;
    }
}
