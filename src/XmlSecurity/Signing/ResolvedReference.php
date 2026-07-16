<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;

/**
 * A resolved Target: the DOM element to be canonicalized and digested and its already-stamped id. Internal
 * to the signing flow, not a public SPI.
 */
final readonly class ResolvedReference
{
    /**
     * @param non-empty-string $id the bare id value, without the '#' fragment prefix
     */
    public function __construct(
        public Element $element,
        public string $id,
    ) {
    }
}
