<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\Algorithm\OaepHash;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

/**
 * Builds the xenc:EncryptedKey element wrapping the session key under the recipient's public key.
 *
 *   xenc:EncryptedKey
 *     xenc:EncryptionMethod Algorithm="<keyEncryptionMethod>"
 *     ds:KeyInfo            [result of the KeyIdentifier strategy]
 *     xenc:CipherData
 *       xenc:CipherValue    [base64 of the wrapped key, or a pointer at wherever a sink put it]
 *
 * The xenc:ReferenceList naming the encrypted parts is not a child of this element. The key is written when it
 * is minted, which is before any block has said what it will encrypt, and the same key may be consumed by a
 * signature that never encrypts anything. A list nested here would therefore have to be appended after the
 * fact, to an element a signature may already cover.
 *
 * Returns a detached element; the caller appends it to the Security header. The ds:KeyInfo is produced by a
 * KeyIdentifier strategy, the same seam the signing side uses.
 */
final class EncryptedKeyBuilder
{
    public function __construct(
        private readonly CipherValueElement $cipherValueElement = new CipherValueElement(),
    ) {
    }

    public function build(
        Document $document,
        string $wrappedKey,
        KeyIdentifier $keyIdentifier,
        KeyTransportAlgorithm $keyTransportAlgorithm,
    ): Element {
        $keyInfo = $keyIdentifier->apply($document);

        return $document->map(namespaced_element(
            Namespaces::Xenc->value,
            Namespaces::Xenc->qualify('EncryptedKey'),
            children(
                fn (): Element => $this->buildEncryptionMethod($document, $keyTransportAlgorithm),
                static fn (): Element => $keyInfo,
                fn (): Element => $document->map(namespaced_element(
                    Namespaces::Xenc->value,
                    Namespaces::Xenc->qualify('CipherData'),
                    children(
                        fn (): Element => $this->cipherValueElement->build($document, $wrappedKey),
                    ),
                )),
            ),
        ));
    }

    private function buildEncryptionMethod(Document $document, KeyTransportAlgorithm $algorithm): Element
    {
        // SHA-1 OAEP carries no DigestMethod / MGF children: the spec defaults are SHA-1 / MGF1-SHA1, so a bare
        // EncryptionMethod stays byte-identical to peers and to prior output. SHA-256 is declared explicitly.
        $labelHash = $algorithm->labelHash;
        $mgfHash = $algorithm->mgfHash;
        if (!$algorithm->isOaep() || $labelHash === null || $mgfHash === null) {
            return $this->bareEncryptionMethod($document, $algorithm);
        }

        $declared = [];
        if ($labelHash !== OaepHash::Sha1) {
            $declared[] = static fn (): Element => $document->map(namespaced_element(
                Namespaces::Ds->value,
                Namespaces::Ds->qualify('DigestMethod'),
                attribute('Algorithm', $labelHash->digestMethod()->value),
            ));
        }

        // xenc11:MGF parameterizes the xenc11 rsa-oaep URI only. Under the legacy mgf1p URI the mask is already
        // fixed to MGF1-SHA1, so declaring it there would be an element the URI does not take -- and one this
        // library's own resolver refuses, leaving the output undecryptable even by itself.
        if ($algorithm->method !== KeyEncryptionMethod::RSA_OAEP_MGF1P && $mgfHash !== OaepHash::Sha1) {
            $declared[] = static fn (): Element => $document->map(namespaced_element(
                Namespaces::Xenc11->value,
                Namespaces::Xenc11->qualify('MGF'),
                attribute('Algorithm', $mgfHash->mgfUri()),
            ));
        }

        if ($declared === []) {
            return $this->bareEncryptionMethod($document, $algorithm);
        }

        return $document->map(namespaced_element(
            Namespaces::Xenc->value,
            Namespaces::Xenc->qualify('EncryptionMethod'),
            attribute('Algorithm', $algorithm->method->value),
            children(...$declared),
        ));
    }

    private function bareEncryptionMethod(Document $document, KeyTransportAlgorithm $algorithm): Element
    {
        return $document->map(namespaced_element(
            Namespaces::Xenc->value,
            Namespaces::Xenc->qualify('EncryptionMethod'),
            attribute('Algorithm', $algorithm->method->value),
        ));
    }
}
