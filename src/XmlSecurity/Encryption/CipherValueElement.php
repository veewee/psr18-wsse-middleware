<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\XopInclude;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * The xenc:CipherValue for some octets: either the octets themselves as base64, or a pointer at wherever the
 * sink put them.
 *
 * One class rather than the same two-way choice in both builders. The wrapped key and the encrypted content
 * are written by different builders and a peer decides per value which shape it gets, so the two would drift.
 */
final readonly class CipherValueElement
{
    public function __construct(
        private ?CipherValueSink $sink = null,
    ) {
    }

    public function build(Document $document, string $bytes): Element
    {
        if ($this->sink === null) {
            return $document->map(namespaced_element(
                Namespaces::Xenc->value,
                Namespaces::Xenc->qualify('CipherValue'),
                value(base64_encode($bytes)),
            ));
        }

        $reference = $this->sink->store($bytes);

        // The prefix is declared on the xenc:CipherValue itself, which is where a peer writing this shape puts
        // it. Nothing reads the prefix (an include is matched by namespace), but a peer's own parser has to be
        // able to resolve it where it finds it.
        return $document->map(namespaced_element(
            Namespaces::Xenc->value,
            Namespaces::Xenc->qualify('CipherValue'),
            attribute('xmlns:xop', XopInclude::NAMESPACE_URI),
            children(
                static fn (): Element => $document->map(namespaced_element(
                    XopInclude::NAMESPACE_URI,
                    'xop:Include',
                    attribute('href', $reference),
                )),
            ),
        ));
    }
}
