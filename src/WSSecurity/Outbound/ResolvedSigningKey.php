<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use SensitiveParameter;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * What a SigningKey resolved to for the message in flight: the key the signature is computed with, and how
 * ds:KeyInfo points a receiver at it.
 *
 * There is no certificate here. A symmetric signature has none, and the key identifier already knows whatever
 * it references, so carrying one would be a field that is meaningful for one kind of signing key and empty for
 * the other.
 */
final readonly class ResolvedSigningKey
{
    public function __construct(
        #[SensitiveParameter] public Key|SessionKey $key,
        public KeyIdentifier $keyIdentifier,
    ) {
    }
}
