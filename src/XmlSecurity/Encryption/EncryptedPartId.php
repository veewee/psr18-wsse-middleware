<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

/**
 * The id stamped on one xenc:EncryptedData element, used to emit the xenc:DataReference URI inside the
 * xenc:EncryptedKey's xenc:ReferenceList. The id is the bare value, without the '#' fragment prefix.
 */
final readonly class EncryptedPartId
{
    /**
     * @param non-empty-string $id
     */
    public function __construct(
        public string $id,
    ) {
    }
}
