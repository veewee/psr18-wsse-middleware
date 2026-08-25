<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * The inbound counterpart of ExternalPartEncryption: the parts available to decrypt, plus the one @Type and the
 * one transform the message is required to declare.
 *
 * Required, not merely expected. Anything else is refused before any decryption work happens, so a peer cannot
 * pick a mode this package does not implement and have the bytes attempted anyway.
 */
final readonly class ExternalPartDecryption
{
    /**
     * @param non-empty-string $type
     * @param non-empty-string $transform
     */
    public function __construct(
        public ExternalPartList $parts,
        public string $type,
        public string $transform,
    ) {
    }
}
