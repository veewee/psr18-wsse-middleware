<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;

/**
 * A resolved Part: the DOM element to be canonicalized and digested, its already-stamped wsu:Id, and the Part
 * descriptor that produced it (kept for diagnostic messages). Internal to the signing flow, not a public SPI.
 */
final readonly class ResolvedReference
{
    /**
     * @param non-empty-string $wsuId the bare id value, without the '#' fragment prefix
     */
    public function __construct(
        public Element $element,
        public string $wsuId,
        public Part $part,
    ) {
    }
}
