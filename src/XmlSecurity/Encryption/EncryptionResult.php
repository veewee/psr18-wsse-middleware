<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * What an encryption operation produced outside the document: each external part under its original reference,
 * its content now the ciphertext framing a receiver expects.
 *
 * The engine returns these rather than writing them anywhere. It has no idea where a part's bytes live, and
 * handing it something that could write them would put caller code inside a crypto operation.
 */
final readonly class EncryptionResult
{
    public function __construct(
        public ExternalPartList $sealedParts,
    ) {
    }
}
