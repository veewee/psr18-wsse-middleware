<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use VeeWee\Xml\Dom\Document;

/**
 * Resolves the key an xenc:EncryptedData was encrypted under, for a message that carries no xenc:EncryptedKey
 * because both sides already hold the key.
 *
 * The engine cannot do this itself: which element names the key, and how, is a profile's vocabulary. What the
 * engine owns is the rule that a key resolved this way must already be established, so this returns null rather
 * than searching further, and null is a refusal to the caller.
 *
 * Asked per xenc:EncryptedData rather than once per message, because a message may legitimately protect
 * different parts under different keys, and nothing in the format says otherwise.
 */
interface SessionKeyResolver
{
    public function resolve(Document $document, Element $encryptedData): ?SessionKey;
}
