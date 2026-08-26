<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * A materialized symmetric key: the bytes, the two ways a consumer points a ds:KeyInfo at it, and every form an
 * inbound reference may use to name it.
 *
 * Two references rather than one, because the two wire positions are referenced differently by the stacks that
 * emit this shape. A ds:Signature names the key itself, by an identifier that stays valid however the key
 * travels; an xenc:EncryptedData in the same header names the element carrying it, by wsu:Id. Sources with no
 * carrying element hand over the same reference for both.
 *
 * The wire identifiers travel with the key rather than being registered separately, because a key nothing can
 * name inbound is a response nobody can verify. ExchangeKeys establishes them itself when it materializes the
 * key, so no call site can forget to.
 */
final readonly class SymmetricKey
{
    /**
     * @param list<non-empty-string> $wireIdentifiers
     * @param ?KeyIdentifier         $localKeyIdentifier how an element in the same Security header names the
     *        key; null when the key has no carrying element to point at, in which case the general reference
     *        serves both positions
     */
    public function __construct(
        public SessionKey $bytes,
        public KeyIdentifier $keyIdentifier,
        public array $wireIdentifiers = [],
        private ?KeyIdentifier $localKeyIdentifier = null,
    ) {
    }

    public function localKeyIdentifier(): KeyIdentifier
    {
        return $this->localKeyIdentifier ?? $this->keyIdentifier;
    }

    /**
     * @return positive-int
     */
    public function length(): int
    {
        $length = strlen($this->bytes->bytes());

        /** @var positive-int */
        return $length;
    }
}
