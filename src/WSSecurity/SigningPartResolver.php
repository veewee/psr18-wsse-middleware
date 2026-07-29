<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdMinter;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;
use VeeWee\Xml\Dom\Document;

/**
 * Lowers the Parts an outbound signature covers to engine Targets. Static parts (Body/Element/Id) lower directly
 * via Part::toTarget; the dynamic parts (securityHeaderContents, soapHeaders) are expanded against the live
 * header, stamping a wsu:Id on each matched element (idempotent: an id an earlier block already minted is
 * reused) and targeting it by that id.
 *
 * Named for signing, not merely for outbound, because signing is the only direction that mints: the Encryption
 * block is outbound too and deliberately does not come here — it refuses a dynamic part outright, since a
 * signing-only part is not encryptable, and it needs an encryption mode alongside each Target.
 *
 * Nothing inbound may resolve parts through this class. RequiredPartsValidator expands the same dynamic parts
 * via DynamicPartMembers and lowers the static ones with Part::toTarget, but it holds no IdMinter at all, and
 * that is the point: a signed element already carries the wsu:Id its ds:Reference used, so minting on inbound
 * could only invent an id for an element the signature never covered. Handing that class a minter would make
 * the mistake representable; leaving it without one makes it impossible.
 */
final readonly class SigningPartResolver
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
            $dynamic = DynamicPartMembers::forPart($part, $securityHeader);
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
