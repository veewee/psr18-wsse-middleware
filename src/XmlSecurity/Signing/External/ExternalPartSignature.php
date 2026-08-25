<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\SigningRequest;

/**
 * The external parts one signing operation covers, plus the transform every one of their references declares.
 *
 * The transform is per-message rather than per-part, which is why it lives here instead of on ExternalPart,
 * and why this type exists rather than two more parameters on SigningRequest. It carries no key material and
 * no store, so it is a value the profile layer fills in: the engine is told which transform to declare and
 * never decides that a reference happens to be an attachment.
 */
final readonly class ExternalPartSignature
{
    /**
     * @param non-empty-string $transform
     */
    public function __construct(
        public ExternalPartList $parts,
        public string $transform,
    ) {
    }
}
