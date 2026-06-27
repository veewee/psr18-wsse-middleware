<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;

/**
 * The exact element instances a verified signature covered. This is the XML Signature Wrapping defense
 * currency: wasSigned() compares by object identity, so a post-verification DOM swap cannot pass an unsigned
 * look-alike off as signed.
 */
final readonly class VerifiedReferences
{
    /**
     * @param list<Element> $elements
     */
    public function __construct(
        private array $elements,
    ) {
    }

    public function wasSigned(Element $element): bool
    {
        foreach ($this->elements as $signed) {
            if ($signed === $element) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    public function signedIds(): array
    {
        $ids = [];
        foreach ($this->elements as $element) {
            // The new Dom\ API returns null for an absent attribute (unlike the old DOM "" sentinel).
            $id = $element->getAttributeNS(WsseNamespace::Wsu->value, 'Id');
            if ($id !== null) {
                $ids[] = $id;
            }
        }

        return $ids;
    }
}
