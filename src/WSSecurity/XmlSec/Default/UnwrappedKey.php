<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Default;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DataEncryptionMethod;

/**
 * The raw session key bytes recovered from an xenc:EncryptedKey, together with the data-encryption method
 * declared on that element. The method is informational: each xenc:EncryptedData carries its own
 * xenc:EncryptionMethod that the reader honours, so different parts may legally use different ciphers under
 * the same session key. The key bytes are ephemeral (generated per operation, never stored) and so are not
 * wrapped in a HiddenString here.
 */
final readonly class UnwrappedKey
{
    public function __construct(
        public string $sessionKey,
        public DataEncryptionMethod $dataEncryptionMethod,
    ) {
    }
}
