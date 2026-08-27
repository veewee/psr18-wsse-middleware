<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

/**
 * Builds the xenc:ReferenceList naming every xenc:EncryptedData one encryption operation produced.
 *
 *   xenc:ReferenceList
 *     xenc:DataReference URI="#<id>" [one per encrypted part]
 *
 * Returns a detached element the caller places beside the key that unlocks the parts. Standing on its own
 * rather than nested in the xenc:EncryptedKey is what lets one key serve a signature and an encryption
 * together: the key is written when it is minted, and the list only exists once a block has encrypted
 * something.
 */
final class ReferenceListBuilder
{
    /**
     * @param non-empty-list<non-empty-string> $encryptedPartIds
     */
    public function build(Document $document, array $encryptedPartIds): Element
    {
        $references = array_map(
            static fn (string $partId): callable => static fn (): Element => $document->map(namespaced_element(
                Namespaces::Xenc->value,
                Namespaces::Xenc->qualify('DataReference'),
                attribute('URI', '#'.$partId),
            )),
            $encryptedPartIds,
        );

        return $document->map(namespaced_element(
            Namespaces::Xenc->value,
            Namespaces::Xenc->qualify('ReferenceList'),
            children(...$references),
        ));
    }
}
