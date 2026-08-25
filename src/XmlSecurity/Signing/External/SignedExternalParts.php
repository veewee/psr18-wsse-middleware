<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * Which external parts the signature actually covered.
 *
 * Reported rather than assumed, so a block can assert coverage instead of trusting that what it registered is
 * what got signed. An empty list is the normal answer for a message with no external parts.
 */
final readonly class SignedExternalParts
{
    public function __construct(
        public ExternalPartList $covered,
    ) {
    }
}
