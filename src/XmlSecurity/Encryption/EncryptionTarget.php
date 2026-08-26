<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\XmlSecurity\Target;

/**
 * One region to encrypt, paired with the XML-Enc mode it is encrypted in. The mode (Content vs Element) is a
 * caller decision: the WS-Security profile encrypts the SOAP Body and Timestamp as Content and other elements
 * whole as Element, but XML-Security itself takes the choice as input rather than deriving it.
 */
final readonly class EncryptionTarget
{
    public function __construct(
        public Target $target,
        public EncryptionMode $mode,
    ) {
    }
}
