<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use VeeWee\Xml\Dom\Document;

/**
 * Lowers the configured signature Parts to engine Targets. Static parts (Body/Element/Id) lower directly via
 * Part::toTarget; the dynamic parts (securityHeaderContents, soapHeaders) are expanded against the live header,
 * stamping a wsu:Id on each matched element (idempotent: an id an earlier block already minted is reused) and
 * targeting it by that id. Only signing expands dynamic parts, so this seam is outbound-only — the inbound
 * required-parts check uses Part::toTarget directly and never mints.
 */
final readonly class PartResolver
{
    public function __construct(
        private IdMinter $idMinter,
    ) {
    }

    /**
     * @param non-empty-list<Part> $parts
     *
     * @return non-empty-list<Target>
     *
     * @throws WsseHeaderException when the parts match no element to sign
     */
    public function resolve(array $parts, Document $document, SoapVersion $soapVersion, Element $securityHeader): array
    {
        $targets = [];
        foreach ($parts as $part) {
            $dynamic = DynamicPartMembers::forPart($part, $document, $securityHeader);
            if ($dynamic !== null) {
                foreach ($dynamic as $element) {
                    $targets[] = Target::byId($this->idMinter->mint($element, $document));
                }

                continue;
            }

            $targets[] = $part->toTarget($soapVersion);
        }

        if ($targets === []) {
            throw WsseHeaderException::nothingToSign();
        }

        return $targets;
    }
}
