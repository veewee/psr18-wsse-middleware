<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Encryption;

use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\OpenSSL\CipherText;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\WSSecurity\Wsse\WsuIdMinter;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespace;
use Throwable;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;
use function VeeWee\Xml\Dom\Manipulator\append;
use function VeeWee\Xml\Dom\Manipulator\Node\replace_by_external_node;

/**
 * Serializes one encrypted Part as an xenc:EncryptedData element and replaces the original target node in the
 * document.
 *
 * For Content-mode Parts (soap:Body, wsu:Timestamp) the target element survives: its children are replaced by
 * the single xenc:EncryptedData. For Element-mode Parts the whole element is replaced by the xenc:EncryptedData.
 * The CipherValue carries base64(IV || ciphertext [|| tag]); a wsu:Id is stamped on the xenc:EncryptedData so
 * the xenc:DataReference in the EncryptedKey can address it.
 */
final class EncryptedDataBuilder
{
    public function __construct(
        private readonly WsuIdMinter $idMinter,
    ) {
    }

    /**
     * @throws EncryptionFailed
     */
    public function build(
        Document $document,
        Element $targetElement,
        CipherText $cipherText,
        DataEncryptionMethod $method,
        EncryptionMode $mode,
    ): EncryptedPartId {
        try {
            $cipherValue = base64_encode($cipherText->iv.$cipherText->bytes.($cipherText->tag ?? ''));
            $encryptedData = $this->buildEncryptedData($document, $cipherValue, $method, $mode);
            $id = $this->idMinter->mint($encryptedData, $document);

            $this->place($targetElement, $encryptedData, $mode);

            return new EncryptedPartId($id);
        } catch (EncryptionFailed $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw EncryptionFailed::withReason($exception->getMessage());
        }
    }

    private function buildEncryptedData(
        Document $document,
        string $cipherValue,
        DataEncryptionMethod $method,
        EncryptionMode $mode,
    ): Element {
        return $document->map(namespaced_element(
            WsseNamespace::Xenc->value,
            WsseNamespace::Xenc->qualify('EncryptedData'),
            attribute('Type', $mode->value),
            children(
                static fn (): Element => $document->map(namespaced_element(
                    WsseNamespace::Xenc->value,
                    WsseNamespace::Xenc->qualify('EncryptionMethod'),
                    attribute('Algorithm', $method->value),
                )),
                static fn (): Element => $document->map(namespaced_element(
                    WsseNamespace::Xenc->value,
                    WsseNamespace::Xenc->qualify('CipherData'),
                    children(
                        static fn (): Element => $document->map(namespaced_element(
                            WsseNamespace::Xenc->value,
                            WsseNamespace::Xenc->qualify('CipherValue'),
                            value($cipherValue),
                        )),
                    ),
                )),
            ),
        ));
    }

    private function place(Element $targetElement, Element $encryptedData, EncryptionMode $mode): void
    {
        if ($mode === EncryptionMode::Element) {
            replace_by_external_node($targetElement, $encryptedData);

            return;
        }

        // Content mode: drop the element's existing children, then attach the single xenc:EncryptedData child.
        /** @var ?Node $child */
        $child = $targetElement->firstChild;
        while ($child !== null) {
            $targetElement->removeChild($child);
            /** @var ?Node $child */
            $child = $targetElement->firstChild;
        }

        append($encryptedData)($targetElement);
    }
}
