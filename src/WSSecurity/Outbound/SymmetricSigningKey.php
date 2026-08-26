<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\SymmetricKeySource;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;

/**
 * Signs with a symmetric secret: a keyed MAC rather than a signature, which is what a WS-SecurityPolicy
 * SymmetricBinding asks for. The source decides where the secret comes from and how ds:KeyInfo names it; this
 * class only states how many bytes the chosen MAC wants.
 *
 * Passing the same source to an Encryption block is what makes the two share one key.
 *
 * @internal a Signature block takes a SymmetricKeySource itself and adapts it here, since there is nothing to
 *           configure on the way through
 */
final readonly class SymmetricSigningKey implements SigningKey
{
    public function __construct(
        private SymmetricKeySource $source,
    ) {
    }

    public function resolve(WsseContext $context, SignatureMethod $method): ResolvedSigningKey
    {
        if ($method->keyKind() !== SignatureKeyKind::Hmac) {
            throw new InvalidArgumentException(sprintf(
                '%s is keyed by private key material; a symmetric secret cannot provide it.',
                $method->name,
            ));
        }

        // Preferred rather than required: HMAC pads a short key and hashes a long one, so a session key minted
        // for a cipher of a different width still keys this MAC.
        $key = $this->source->resolve($context, KeyRequest::preferably($method->hmacKeyLength()));

        return new ResolvedSigningKey($key->bytes, $key->keyIdentifier);
    }
}
