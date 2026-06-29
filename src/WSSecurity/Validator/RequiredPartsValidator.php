<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Validator;

use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\PartLocator;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Verification\VerifiedReferences;
use VeeWee\Xml\Dom\Document;

/**
 * Asserts that every required part of the message is present in the set of elements a signature actually
 * covered. The check is by object identity, not by id or by structure: the locator resolves each required part
 * to the live element instance, and the signed set is compared against that same instance. An attacker who
 * relocates or duplicates a signed-looking element produces a different instance, so the swap cannot satisfy
 * the requirement. The locator is the hardened one the verifier itself uses, so both sides agree on which node
 * a part addresses.
 */
final class RequiredPartsValidator
{
    public function __construct(
        private readonly PartLocator $partLocator,
    ) {
    }

    /**
     * @param list<Part> $requiredParts
     *
     * @throws SecurityFault
     */
    public function validate(Document $document, VerifiedReferences $signedElements, array $requiredParts): void
    {
        foreach ($requiredParts as $part) {
            try {
                $element = $this->partLocator->locate($document, $part);
            } catch (IdReferenceException $exception) {
                throw SecurityFault::inboundFailure($exception);
            }

            if (!$signedElements->wasSigned($element)) {
                throw SecurityFault::inboundFailure();
            }
        }
    }
}
