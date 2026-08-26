<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
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
 *
 * The reference declares a wsse11:TokenType saying it points at a session key. A receiver enforcing the Basic
 * Security Profile classifies a reference by that attribute, and refuses one it cannot classify: without it the
 * message is rejected for the shape the receiver guessed at instead.
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

    /**
     * The identifier a wrapped key is named by, computed from the bytes rather than stated alongside them.
     *
     * The digest is over the wrapped bytes as they travel, not over the plaintext session key, which is what
     * makes it something both sides can compute without either revealing the secret.
     *
     * @param string $wrapped the cipher bytes of the xenc:EncryptedKey, before base64
     */
    public static function forWrappedKey(string $wrapped): self
    {
        /** @var non-empty-string $base64Sha1 */
        $base64Sha1 = base64_encode((new Digest())->hash($wrapped, DigestMethod::SHA1));

        return new self($base64Sha1);
    }

    /**
     * The identifier as it is written and as an inbound reference names it, for a caller that has to register
     * the key under it as well as point at it.
     *
     * @return non-empty-string
     */
    public function value(): string
    {
        return $this->base64Sha1;
    }

    public function apply(Document $document): Element
    {
        return SecurityTokenReference::keyIdentifier(
            $this->base64Sha1,
            WsSecurityValueType::EncryptedKeySha1->value,
            WsSecurityEncodingType::Base64Binary->value,
            WsSecurityValueType::EncryptedKey->value,
        )->buildKeyInfo($document);
    }
}
