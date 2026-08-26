<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\SessionKeyResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\IdLookup;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;
use VeeWee\Xml\Dom\Document;

/**
 * Reads the ds:KeyInfo of an xenc:EncryptedData and hands back the session key this exchange established under
 * the reference it names. What a symmetric binding\'s response carries instead of an xenc:EncryptedKey: the key
 * travelled with the request, so the answer only points at it.
 *
 * The reference forms are the same ones a signature\'s ds:KeyInfo may use, read by the same class, so the two
 * paths cannot come to disagree about what a reference means.
 */
final readonly class EstablishedSessionKeyResolver implements SessionKeyResolver
{
    private EstablishedSecrets $secrets;

    public function __construct(
        ExchangeKeys $keys,
        private IdLookup $idLookup,
    ) {
        $this->secrets = new EstablishedSecrets($keys);
    }

    public function resolve(Document $document, Element $encryptedData): ?SessionKey
    {
        $keyInfo = OnlyChild::named($encryptedData, Namespaces::Ds, 'KeyInfo');
        if ($keyInfo === null) {
            return null;
        }

        $str = OnlyChild::named($keyInfo, WsseNamespaces::Wsse, 'SecurityTokenReference');

        return $str === null ? null : $this->secrets->forReference($document, $str, $this->idLookup);
    }
}
