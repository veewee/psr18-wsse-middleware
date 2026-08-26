<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\OpenSSL\Digest;
use Soap\Psr18WsseMiddleware\OpenSSL\KeyTransport;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\CipherValueParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\BinarySecurityToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncKeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\EncryptedKeySha1KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\LocalTokenKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\CipherValueElement;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedKeyBuilder;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\SessionKeyFactory;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * A session key minted here and carried to the recipient wrapped under its public certificate, as an
 * xenc:EncryptedKey in the Security header. The ordinary way a client keys a symmetric binding when the two
 * sides share no secret.
 *
 * What this authenticates is worth stating plainly: nothing. Anyone holding the recipient's certificate, which
 * is public, can mint a key and wrap it, so a request protected only by a signature keyed this way proves
 * possession of no credential. Pair it with an endorsing signature over a certificate you control when the
 * request has to authenticate its sender. A response keyed this way does authenticate the server, because only
 * its private key could have unwrapped the key.
 *
 * The key is minted on the first resolve() and the xenc:EncryptedKey written then, so its position in the header
 * follows whichever block asked first and a message with no symmetric block writes nothing.
 */
final class WrappedSessionKey implements SymmetricKeySource
{
    private readonly SessionKeyFactory $sessionKeyFactory;
    private readonly KeyTransport $keyTransport;
    private readonly EncryptedKeyBuilder $encryptedKeyBuilder;
    private readonly Digest $digest;

    /**
     * @param ?DataEncryptionMethod $keyLength fixes the key's width up front, for a deployment whose blocks
     *        disagree about it or which wants it stated. Null takes the width from the first block that asks,
     *        which is the common case: the wrapped bytes are fixed once written, so a later block asking for a
     *        different mandatory width is refused rather than silently served the wrong key
     * @param ?ExternalParts $optimizedCipherBytes writes the wrapped key into a MIME part and leaves an
     *        xop:Include where its xenc:CipherValue would have been. Pass the same registration the Encryption
     *        block was given when both values should travel that way: whether an element's cipher value is
     *        optimized is decided per element, so the key and the content are separate choices
     */
    public function __construct(
        private readonly Certificate $recipient,
        private readonly EncKeyRef $keyRef = EncKeyRef::SubjectKeyIdentifier,
        private readonly ?DataEncryptionMethod $keyLength = null,
        private readonly SymmetricKeyReference $referencedAs = SymmetricKeyReference::EncryptedKeySha1,
        private readonly ?KeyTransportAlgorithm $keyTransportAlgorithm = null,
        ?ExternalParts $optimizedCipherBytes = null,
    ) {
        $this->sessionKeyFactory = new SessionKeyFactory();
        $this->keyTransport = new KeyTransport();
        $this->encryptedKeyBuilder = new EncryptedKeyBuilder(new CipherValueElement(
            $optimizedCipherBytes === null ? null : new CipherValueParts($optimizedCipherBytes),
        ));
        $this->digest = new Digest();
    }

    public function resolve(WsseContext $context, KeyRequest $for): SymmetricKey
    {
        $key = $context->keys()->materialize($this, fn (): SymmetricKey => $this->mint($context, $for));

        if ($for->mandatory && $key->length() !== $for->bytes) {
            // A key of the wrong width fails at the peer with nothing local to explain it, so the mismatch is
            // named here instead. Both numbers appear: which of the two is wrong is the caller's to decide.
            throw new InvalidArgumentException(sprintf(
                'The session key this source carries is %d bytes and this block needs exactly %d. '
                .'Fix the block\'s algorithm or state the width on the key source.',
                $key->length(),
                $for->bytes,
            ));
        }

        return $key;
    }

    private function mint(WsseContext $context, KeyRequest $for): SymmetricKey
    {
        $document = $context->document();
        $header = SecurityHeader::forContext($context);

        $sessionKey = $this->sessionKeyFactory->generate($this->keyLength?->keyLength() ?? $for->bytes);
        $algorithm = $this->keyTransportAlgorithm ?? KeyTransportAlgorithm::fromMethod(
            $context->profile()->crypto()->keyEncryptionMethod(),
            $context->profile()->crypto()->oaepHash(),
        );
        $wrapped = $this->keyTransport->wrap($sessionKey, $this->recipient, $algorithm);

        $encryptedKey = $this->encryptedKeyBuilder->build(
            $document,
            $wrapped,
            $this->recipientReference($context),
            $algorithm,
        );
        $header->appendChildren(static fn (): \Dom\Element => $encryptedKey);
        $wsuId = (new WsuIdConvention())->minter()->mint($encryptedKey, $document);

        // The digest is over the wrapped bytes as they travel, not over the plaintext key. That is what makes
        // it something both sides can compute without either revealing the secret.
        /** @var non-empty-string $sha1 */
        $sha1 = base64_encode($this->digest->hash($wrapped, DigestMethod::SHA1));

        return new SymmetricKey(
            $sessionKey,
            $this->referencedAs === SymmetricKeyReference::EncryptedKeySha1
                ? new EncryptedKeySha1KeyIdentifier($sha1)
                : new LocalTokenKeyIdentifier($wsuId),
            // Both forms, whichever this message emits: a peer may name the key by either in its response, and
            // which one it picks is not ours to constrain.
            [$sha1, '#'.$wsuId],
            $encryptedKey,
        );
    }

    /**
     * How the xenc:EncryptedKey names the certificate whose private key unwraps it.
     */
    private function recipientReference(WsseContext $context): KeyIdentifier
    {
        return match ($this->keyRef) {
            EncKeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier($this->recipient),
            EncKeyRef::IssuerSerial => new IssuerSerialKeyIdentifier($this->recipient),
            EncKeyRef::Thumbprint => new ThumbprintKeyIdentifier($this->recipient),
            EncKeyRef::BinarySecurityToken => (new BinarySecurityToken($this->recipient))
                ->embedAsDirectReference($context),
        };
    }
}
