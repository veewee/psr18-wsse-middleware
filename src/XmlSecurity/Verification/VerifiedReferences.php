<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Verification;

use Dom\Element;

/**
 * The exact element instances a verified signature covered, each paired with the id its ds:Reference used.
 * This is the XML Signature Wrapping defense currency: wasSigned() compares by object identity, so a
 * post-verification DOM swap cannot pass an unsigned look-alike off as signed. The ids come from the reference
 * URIs the verifier resolved, so this type carries no id-attribute convention of its own.
 */
final readonly class VerifiedReferences
{
    /**
     * @param list<Element>          $elements the covered element instances, in reference order
     * @param list<non-empty-string> $ids      the bare id each reference used, in the same order
     */
    public function __construct(
        private array $elements,
        private array $ids = [],
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
     * @return list<non-empty-string>
     */
    public function signedIds(): array
    {
        return $this->ids;
    }
}
