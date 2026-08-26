<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\KeyStore;

use ParagonIE\HiddenString\HiddenString;
use SensitiveParameter;

/**
 * A symmetric session key: the raw bytes used for bulk data encryption and carried, wrapped, in a
 * ds:EncryptedKey. The bytes are held inside a HiddenString so the key stays out of exception messages and
 * var dumps, the same protection the asymmetric Key value object gives.
 */
final class SessionKey
{
    private HiddenString $bytes;

    private function __construct(#[SensitiveParameter] string $bytes)
    {
        $this->bytes = new HiddenString($bytes);
    }

    public static function fromBytes(#[SensitiveParameter] string $bytes): self
    {
        return new self($bytes);
    }

    public function bytes(): string
    {
        return $this->bytes->getString();
    }
}
