<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

/**
 * How a consumer of a wrapped session key points back at the xenc:EncryptedKey that carries it. One of:
 *   EncryptedKeySha1 -- a wsse:KeyIdentifier holding base64(SHA-1(wrapped cipher bytes)), the WSS 1.1 form
 *                       every stack that implements a symmetric binding emits
 *   DirectReference  -- a wsse:Reference URI="#..." naming the local xenc:EncryptedKey by its wsu:Id
 *
 * Both name the same key. The SHA-1 form survives the key being carried anywhere in the message, while the
 * direct reference is shorter and needs the token to sit in the same header.
 */
enum SymmetricKeyReference
{
    case EncryptedKeySha1;
    case DirectReference;
}
