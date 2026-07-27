<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Validator;

use Soap\Psr18WsseMiddleware\WSSecurity\DynamicPartMembers;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\SecurityFault;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\SoapVersion;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\Xml\Exception\IdReferenceException;
use Soap\Psr18WsseMiddleware\XmlSecurity\TargetLocator;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\VerifiedReferences;
use VeeWee\Xml\Dom\Document;

/**
 * Asserts that every required part of the message is present in the set of elements a signature actually
 * covered. The check is by object identity, not by id or by structure: the locator resolves each required part
 * to the live element instance, and the signed set is compared against that same instance. An attacker who
 * relocates or duplicates a signed-looking element produces a different instance, so the swap cannot satisfy
 * the requirement. The locator is the hardened one the verifier itself uses, so both sides agree on which node
 * a part addresses.
 *
 * A dynamic required part (securityHeaderContents/soapHeaders) is expanded against the received message and
 * every member it resolves to must have been signed; unlike the outbound side it never mints, since a signed
 * element already carries the wsu:Id its ds:Reference used. A dynamic part that expands to no member is
 * vacuously satisfied.
 */
final class RequiredPartsValidator
{
    public function __construct(
        private readonly TargetLocator $targetLocator,
    ) {
    }

    /**
     * @param list<Part> $requiredParts
     *
     * @throws SecurityFault
     */
    public function validate(
        Document $document,
        SoapVersion $soapVersion,
        VerifiedReferences $signedElements,
        array $requiredParts,
    ): void {
        try {
            $securityHeader = SecurityHeader::locate($document, $soapVersion);
        } catch (WsseHeaderException $exception) {
            throw SecurityFault::inboundFailure($exception);
        }

        foreach ($requiredParts as $part) {
            if ($part->kind()->isDynamic()) {
                // No header to expand against means the requirement cannot be met, and must not pass by
                // expanding to nothing: the wsse:Security element is not itself a signed reference target, so
                // stamping an actor/role on the genuine header — or moving it out of the SOAP header — is a
                // signature-preserving way to make it read as some other hop's and slip the check.
                if ($securityHeader === null) {
                    throw SecurityFault::inboundFailure();
                }

                $dynamic = DynamicPartMembers::forPart($part, $securityHeader) ?? [];
                foreach ($dynamic as $member) {
                    if (!$signedElements->wasSigned($member)) {
                        throw SecurityFault::inboundFailure();
                    }
                }

                continue;
            }

            try {
                $element = $this->targetLocator->locate($document, $part->toTarget($soapVersion));
            } catch (IdReferenceException $exception) {
                throw SecurityFault::inboundFailure($exception);
            }

            if (!$signedElements->wasSigned($element)) {
                throw SecurityFault::inboundFailure();
            }
        }
    }
}
