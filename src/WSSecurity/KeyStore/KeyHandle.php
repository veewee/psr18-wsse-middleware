<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

/**
 * Names the key/certificate material a KeyResolver should resolve. Distinct from the KeyIdentifier\ types
 * (the WSSE STR reference types that go in the XML). The HiddenString-wrapped material stays wrapped here;
 * it is only unwrapped inside the OpenSSL\ boundary by the resolver.
 */
final readonly class KeyHandle
{
    private function __construct(
        private KeyInterface $material,
    ) {
    }

    public static function for(KeyInterface $material): self
    {
        return new self($material);
    }

    public function material(): KeyInterface
    {
        return $this->material;
    }
}
