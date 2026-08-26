<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;

/**
 * What a decryption operation produced outside the document: only the parts an xenc:EncryptedData actually
 * named, opened, with the media type the element declared restored.
 *
 * Only those parts, which is the property a caller depends on. A part that arrived in the clear is absent
 * here, so writing this list back cannot silently drop it.
 */
final readonly class DecryptionResult
{
    public function __construct(
        public ExternalPartList $openedParts,
    ) {
    }
}
