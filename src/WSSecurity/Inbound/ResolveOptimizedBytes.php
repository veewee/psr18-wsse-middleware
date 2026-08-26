<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Inbound;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\OptimizedContentException;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsseNamespaces;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\Query;
use Soap\Psr18WsseMiddleware\Xml\XopInclude;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;
use Throwable;
use VeeWee\Xml\Dom\Document;

/**
 * Puts back the bytes a peer moved out of the document, so every reader after this one sees the message it
 * would have received from a peer that inlined them.
 *
 * A peer with MTOM enabled writes an xop:Include where a security value belongs and carries the raw bytes in
 * a MIME part beside the envelope, skipping the 33% base64 costs. Nothing negotiates this and no policy
 * assertion expresses it: Apache CXF turns it on by default whenever MTOM is on, and .NET and Metro do it to
 * any large encrypted content unconditionally. So a message arrives in this shape without either side having
 * chosen it, and without this block it is refused as a cipher value that will not decode.
 *
 * Register it first in the inbound list, ahead of Decrypt and VerifySignature. Both of those read values this
 * block restores, and neither knows how to.
 *
 * Three elements are restored and no others: the xenc:CipherValue of an xenc:EncryptedData or an
 * xenc:EncryptedKey, and a wsse:BinarySecurityToken. Those are the three a peer optimizes. An include
 * anywhere else in the message is ordinary MTOM content belonging to the layer that packages attachments, and
 * is left exactly as it is.
 *
 * Registering this block is not a requirement that the shape be present. The peers switch on a size
 * threshold, so one message routinely carries an optimized xenc:EncryptedData beside an inline
 * xenc:EncryptedKey, and the next message carries neither. Every value is decided on its own.
 *
 * A reference is resolved against the supplied parts or refused. Nothing is fetched, whatever scheme the
 * reference names. Every refusal leaves as the one uniform SecurityFault, like everything else inbound.
 */
final class ResolveOptimizedBytes implements InboundAction
{
    /**
     * The upper bound on optimized values one message may declare, a conservative ceiling far above any
     * legitimate message and the same one the decryptor puts on encrypted parts. Enforced before a single
     * part is read, because a small message would otherwise aim an unbounded amount of base64 work.
     */
    public const int MAX_OPTIMIZED_ELEMENTS = 32;

    public function __construct(
        private readonly ExternalParts $carriers,
    ) {
    }

    /**
     * @throws SecurityFault
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        try {
            $pointers = $this->pointers($document);
            if ($pointers === []) {
                return;
            }

            if (count($pointers) > self::MAX_OPTIMIZED_ELEMENTS) {
                throw OptimizedContentException::overCap();
            }

            // Collected once the message is known to need it, and inside the try: collecting reads a peer's
            // own MIME parts, so a failure there is an inbound failure like any other.
            $parts = $this->carriers->collectSealed();

            foreach ($pointers as [$element, $reference]) {
                $this->inline($element, $reference, $parts);
            }
        } catch (OptimizedContentException $exception) {
            throw SecurityFault::inboundFailure($exception);
        } catch (Throwable $foreign) {
            // The parts come from a seam a caller implements, so a third-party one raises types this package
            // never declares. The original is chained, so an operator still gets its message and trace.
            throw SecurityFault::inboundFailure($foreign);
        }
    }

    /**
     * Every value standing in for content, paired with the reference it names.
     *
     * A value holding an include that is not its whole content is refused here rather than skipped. Text
     * beside a pointer, two pointers, one nested deeper, or one naming nothing all describe the same content
     * two ways, and reading either would let the other be injected.
     *
     * @return list<array{0: Element, 1: string}>
     *
     * @throws OptimizedContentException
     */
    private function pointers(Document $document): array
    {
        $pointers = [];
        foreach ($this->candidates($document) as $element) {
            $reference = XopInclude::soleHref($element);
            if ($reference !== null) {
                $pointers[] = [$element, $reference];

                continue;
            }

            if (XopInclude::hrefsIn($document, $element) !== []) {
                throw OptimizedContentException::ambiguousValue();
            }
        }

        return $pointers;
    }

    /**
     * The three elements a peer optimizes, wherever they sit.
     *
     * Document-wide rather than scoped to the Security header addressed to this receiver, because an
     * xenc:EncryptedData sits where its content belongs, most often in the Body. Scope is not this block's
     * decision to make either way: restoring a value changes nothing about which values are then read, and
     * Decrypt still reads its wrapped key from the header addressed to it alone.
     *
     * @return list<Element>
     */
    private function candidates(Document $document): array
    {
        return Query::elements(
            $document,
            '//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue'
            .' | //xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue'
            .' | //wsse:BinarySecurityToken',
            null,
            [
                Namespaces::Xenc->prefix() => Namespaces::Xenc->uri(),
                WsseNamespaces::Wsse->prefix() => WsseNamespaces::Wsse->uri(),
            ],
        )->reduce(
            /**
             * @param list<Element> $elements
             *
             * @return list<Element>
             */
            static function (array $elements, Element $element): array {
                $elements[] = $element;

                return $elements;
            },
            [],
        );
    }

    /**
     * Replaces the pointer with the base64 of the part it names, which is the value the element would have
     * carried had the peer not optimized it.
     *
     * An empty part is inlined as an empty value rather than refused. The reader downstream already refuses a
     * cipher value too short for its method, and a second refusal here would be a second distinguishable
     * outcome on the one path whose whole design is to have exactly one.
     *
     * @throws OptimizedContentException
     */
    private function inline(Element $element, string $reference, ExternalPartList $parts): void
    {
        $part = $parts->byReference($reference) ?? throw OptimizedContentException::unsuppliedContent();

        $element->textContent = base64_encode($part->content->rewind()->getContents());
    }
}
