<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecureConversationVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Builds the wsc:DerivedKeyToken that tells a receiver how to derive the same key from a token both sides
 * already share.
 *
 *   wsc:DerivedKeyToken @Algorithm=".../dk/p_sha1"
 *     wsse:SecurityTokenReference   [the token the key is derived from]
 *     wsc:Offset
 *     wsc:Length
 *     wsc:Label
 *     wsc:Nonce                     [base64]
 *
 * The children are emitted in schema order, which is a sequence rather than a set: a receiver validating against
 * the schema refuses a token whose children are shuffled.
 *
 * wsc:Offset is written and never wsc:Generation. The two are a schema choice expressing the same position, one
 * as bytes and one as a multiple of the length, and a token carrying both describes two positions.
 *
 * The element is returned detached; the caller appends it and mints its wsu:Id.
 */
final readonly class DerivedKeyToken
{
    /**
     * @param Element          $derivingKeyInfo the ds:KeyInfo a key identifier produced for the token this key
     *        is derived from. A derived-key token carries the reference itself rather than the ds:KeyInfo
     *        wrapper, so the wrapper is unwrapped here: one caller wanting a bare reference is not a reason for
     *        every key-identifier strategy to answer two questions
     * @param non-empty-string $label   the label half of the derivation seed
     * @param non-empty-string $nonce   the raw nonce, base64-encoded into the element
     * @param non-negative-int $offset
     * @param positive-int     $length
     */
    public function __construct(
        private WsSecureConversationVersion $version,
        private Element $derivingKeyInfo,
        private string $label,
        private string $nonce,
        private int $offset,
        private int $length,
    ) {
    }

    /**
     * @throws WsseHeaderException when the deriving ds:KeyInfo carries no security token reference
     */
    public function build(Document $document): Element
    {
        $reference = $this->reference();

        return $document->map(namespaced_element(
            $this->version->value,
            $this->version->qualify('DerivedKeyToken'),
            attribute('Algorithm', $this->version->derivationAlgorithm()),
            children(
                static fn (): Element => $reference,
                fn (): Element => $this->child($document, 'Offset', (string) $this->offset),
                fn (): Element => $this->child($document, 'Length', (string) $this->length),
                fn (): Element => $this->child($document, 'Label', $this->label),
                fn (): Element => $this->child($document, 'Nonce', base64_encode($this->nonce)),
            ),
        ));
    }

    /**
     * The wsse:SecurityTokenReference inside the deriving ds:KeyInfo.
     *
     * @throws WsseHeaderException
     */
    private function reference(): Element
    {
        return ChildElements::single($this->derivingKeyInfo, WsseNamespaces::Wsse, 'SecurityTokenReference')
            ?? throw WsseHeaderException::derivingTokenNotReferenceable();
    }

    private function child(Document $document, string $localName, string $text): Element
    {
        return $document->map(namespaced_element(
            $this->version->value,
            $this->version->qualify($localName),
            value($text),
        ));
    }
}
