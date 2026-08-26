<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityTokenReference;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityEncodingType;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsSecurityValueType;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier as KeyIdentifierInterface;
use VeeWee\Xml\Dom\Document;

/**
 * References a symmetric session key by the SHA-1 of its wrapped bytes: the WSS 1.1 EncryptedKeySHA1 form, as
 * ds:KeyInfo > wsse:SecurityTokenReference > wsse:KeyIdentifier.
 *
 * It names the key rather than the element carrying it, so a receiver resolves it against the session keys it
 * has established rather than by walking the document. That is what lets the reference survive the
 * xenc:EncryptedKey travelling anywhere in the message, or the same key being reused across a correlated
 * response.
 */
final readonly class EncryptedKeySha1KeyIdentifier implements KeyIdentifierInterface
{
    /**
     * @param non-empty-string $base64Sha1 base64(SHA-1(wrapped cipher bytes)), which is the digest of the
     *        wrapped key as it travels, not of the plaintext session key
     */
    public function __construct(
        private string $base64Sha1,
    ) {
    }

    public function apply(Document $document): Element
    {
        return SecurityTokenReference::keyIdentifier(
            $this->base64Sha1,
            WsSecurityValueType::EncryptedKeySha1->value,
            WsSecurityEncodingType::Base64Binary->value,
        )->buildKeyInfo($document);
    }
}
