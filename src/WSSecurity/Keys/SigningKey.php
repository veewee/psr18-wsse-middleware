<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;

/**
 * How a Signature block is keyed, and how its ds:KeyInfo points at that key. The two implementations are the two
 * kinds of signature WS-Security defines: one made with a private key and advertised through a certificate, and
 * one keyed by a symmetric secret both sides hold.
 *
 * Injected rather than selected by a flag, because the certificate case carries a cluster of its own concerns
 * (which reference type, whether to advertise a certification path, where to find a SAML assertion that vouches
 * for the key) that mean nothing to the symmetric one. Resolving may write a carrying token into the Security
 * header first, which is why it takes the context rather than being a value the caller builds up front.
 */
interface SigningKey
{
    /**
     * @param SignatureMethod $method the method the block will sign with, which decides what kind of key is
     *        needed and, for a symmetric one, how many bytes of it
     *
     * @throws InvalidArgumentException when the method needs a kind of key this one cannot provide
     */
    public function resolve(WsseContext $context, SignatureMethod $method): ResolvedSigningKey;
}
