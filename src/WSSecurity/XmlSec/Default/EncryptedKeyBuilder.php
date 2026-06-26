<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Builds the xenc:EncryptedKey element wrapping the session key under the recipient's public key and carrying
 * the ReferenceList that points at every xenc:EncryptedData produced for this operation.
 *
 *   xenc:EncryptedKey
 *     xenc:EncryptionMethod Algorithm="<keyEncryptionMethod>"
 *     ds:KeyInfo            [result of the KeyIdentifier strategy]
 *     xenc:CipherData
 *       xenc:CipherValue    [base64 of the wrapped key]
 *     xenc:ReferenceList
 *       xenc:DataReference URI="#<id>" [one per encrypted part]
 *
 * Returns a detached element; the caller appends it to the Security header. The ds:KeyInfo is produced by the
 * request's KeyIdentifier strategy, exactly as KeyInfoBuilder does for signing.
 */
final class EncryptedKeyBuilder
{
    /**
     * @param non-empty-list<EncryptedPartId> $encryptedPartIds
     */
    public function build(
        Document $document,
        string $wrappedKey,
        KeyIdentifier $keyIdentifier,
        Certificate $recipientCertificate,
        KeyEncryptionMethod $keyEncryptionMethod,
        array $encryptedPartIds,
    ): Element {
        $keyInfo = $keyIdentifier->apply($document, $recipientCertificate);

        return $document->map(namespaced_element(
            WsseNamespace::Xenc->value,
            WsseNamespace::Xenc->qualify('EncryptedKey'),
            children(
                static fn (): Element => $document->map(namespaced_element(
                    WsseNamespace::Xenc->value,
                    WsseNamespace::Xenc->qualify('EncryptionMethod'),
                    attribute('Algorithm', $keyEncryptionMethod->value),
                )),
                static fn (): Element => $keyInfo,
                static fn (): Element => $document->map(namespaced_element(
                    WsseNamespace::Xenc->value,
                    WsseNamespace::Xenc->qualify('CipherData'),
                    children(
                        static fn (): Element => $document->map(namespaced_element(
                            WsseNamespace::Xenc->value,
                            WsseNamespace::Xenc->qualify('CipherValue'),
                            value(base64_encode($wrappedKey)),
                        )),
                    ),
                )),
                fn (): Element => $this->buildReferenceList($document, $encryptedPartIds),
            ),
        ));
    }

    /**
     * @param non-empty-list<EncryptedPartId> $encryptedPartIds
     */
    private function buildReferenceList(Document $document, array $encryptedPartIds): Element
    {
        $references = array_map(
            static fn (EncryptedPartId $partId): callable => static fn (): Element => $document->map(namespaced_element(
                WsseNamespace::Xenc->value,
                WsseNamespace::Xenc->qualify('DataReference'),
                attribute('URI', '#'.$partId->id),
            )),
            $encryptedPartIds,
        );

        return $document->map(namespaced_element(
            WsseNamespace::Xenc->value,
            WsseNamespace::Xenc->qualify('ReferenceList'),
            children(...$references),
        ));
    }
}
