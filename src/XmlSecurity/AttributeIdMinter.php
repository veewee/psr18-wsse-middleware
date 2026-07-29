<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\IdStampFailed;
use Symfony\Component\Uid\Uuid;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\namespaced_attribute;

/**
 * Stamps an id under one IdAttribute. A v4 UUID gives uniqueness without any shared state; the "id-" prefix
 * makes the value a valid XML NCName, which cannot start with a digit.
 *
 * One implementation serves every convention, because the algorithm never varied between them — only the
 * attribute did. Pair it with an AttributeIdLookup built from the same IdAttribute; IdConvention exists so that
 * pairing is not something a caller has to get right.
 */
final readonly class AttributeIdMinter implements IdMinter
{
    public function __construct(
        private IdAttribute $attribute,
    ) {
    }

    /**
     * @return non-empty-string
     *
     * @throws IdStampFailed when the node cannot carry the attribute
     */
    public function mint(Element $node, Document $document): string
    {
        $existing = $this->existingId($node);
        if ($existing !== null) {
            return $existing;
        }

        $id = $this->uniqueId($document);

        try {
            namespaced_attribute($this->attribute->namespaceUri, $this->attribute->qualifiedName, $id)($node);
        } catch (Throwable $exception) {
            throw IdStampFailed::becauseOf($exception);
        }

        return $id;
    }

    /**
     * @return non-empty-string|null
     */
    private function existingId(Element $node): ?string
    {
        // The new Dom\ API returns null for an absent attribute (unlike the old DOM "" sentinel).
        $existing = $node->getAttributeNS($this->attribute->namespaceUri, $this->attribute->localName);

        return $existing === null || $existing === '' ? null : $existing;
    }

    /**
     * @return non-empty-string
     */
    private function uniqueId(Document $document): string
    {
        // A v4 UUID collision is effectively unreachable; the guard guarantees the value is free before
        // stamping. A duplicate already in the document counts as taken, not free, so minting never adds to an
        // existing ambiguity.
        do {
            $id = 'id-'.Uuid::v4()->toRfc4122();
        } while (Query::elements($document, $this->attribute->matches($id))->count() !== 0);

        return $id;
    }
}
