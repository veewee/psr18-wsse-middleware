<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml;

use Dom\Element;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\ExchangeKeys;
use Soap\Psr18WsseMiddleware\Xml\ElementText;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\Xml\SameDocumentId;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\SessionKeyResolver;
use Soap\Psr18WsseMiddleware\XmlSecurity\Verification\KeyInfo\OnlyChild;
use VeeWee\Xml\Dom\Document;

/**
 * Reads the ds:KeyInfo of an xenc:EncryptedData and hands back the session key this exchange established under
 * the reference it names. The two forms are the ones a symmetric binding emits: a wsse:KeyIdentifier carrying
 * an EncryptedKeySHA1, and a wsse:Reference naming an element in the Security header by wsu:Id.
 *
 * It reads a reference and resolves it, and does nothing else. In particular it never reads a key out of the
 * element a reference points at: an element a peer put in the message is not evidence of a key, and only a key
 * this exchange established can open anything.
 */
final readonly class EstablishedSessionKeyResolver implements SessionKeyResolver
{
    public function __construct(
        private ExchangeKeys $keys,
    ) {
    }

    public function resolve(Document $document, Element $encryptedData): ?SessionKey
    {
        $keyInfo = OnlyChild::named($encryptedData, Namespaces::Ds, 'KeyInfo');
        if ($keyInfo === null) {
            return null;
        }

        $str = OnlyChild::named($keyInfo, WsseNamespaces::Wsse, 'SecurityTokenReference');
        if ($str === null) {
            return null;
        }

        $identifier = $this->wireIdentifier($str);

        return $identifier === null ? null : $this->keys->resolve($identifier);
    }

    /**
     * @return non-empty-string|null
     */
    private function wireIdentifier(Element $str): ?string
    {
        $reference = OnlyChild::named($str, WsseNamespaces::Wsse, 'Reference');
        if ($reference !== null) {
            $id = SameDocumentId::parse((string) $reference->getAttribute('URI'));

            return $id === null ? null : '#'.$id;
        }

        $keyIdentifier = OnlyChild::named($str, WsseNamespaces::Wsse, 'KeyIdentifier');
        if ($keyIdentifier === null) {
            return null;
        }

        if (WsSecurityValueType::tryFrom((string) $keyIdentifier->getAttribute('ValueType'))
            !== WsSecurityValueType::EncryptedKeySha1
        ) {
            return null;
        }

        $value = ElementText::trimmed($keyIdentifier);

        return $value === '' ? null : $value;
    }
}
