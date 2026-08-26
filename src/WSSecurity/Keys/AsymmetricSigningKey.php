<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Keys;

use InvalidArgumentException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureKeyKind;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\ClientCertificate;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\BinarySecurityToken;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\IssuerSerialKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\KeyRef;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\SamlAssertionKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\ThumbprintKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\Outbound\KeyReference\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\SamlToken;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * Signs with a private key and advertises the certificate that verifies it. Everything certificate-shaped about
 * a signature lives here: which reference type ds:KeyInfo carries, whether a whole certification path is
 * advertised, and how a Holder-of-Key reference finds the assertion that vouches for the key.
 *
 * For the direct-reference path (KeyRef::BinarySecurityToken) a wsse:BinarySecurityToken is embedded in the
 * Security header and the reference points at it by wsu:Id. For the inline reference types (SKI / IssuerSerial /
 * Thumbprint) no token is embedded; the reference derives its content from the certificate alone.
 */
final readonly class AsymmetricSigningKey implements SigningKey
{
    /**
     * @param ?CertificateChain $path advertises the signer's whole certification path in the embedded token, as
     *        a #X509PKIPathv1 wsse:BinarySecurityToken instead of the leaf certificate alone. Pass one for a
     *        peer that will not complete the chain from its own store and needs the intermediates handed to it;
     *        leave it null otherwise, because a bare certificate is what every stack accepts without
     *        configuration
     *
     * @throws InvalidArgumentException when no token is embedded to carry the path, or when the path does not
     *         start at the signing certificate
     */
    public function __construct(
        private ClientCertificate $certificate,
        private KeyRef $keyRef = KeyRef::BinarySecurityToken,
        private ?CertificateChain $path = null,
    ) {
        if ($path === null) {
            return;
        }

        if ($keyRef !== KeyRef::BinarySecurityToken) {
            // The inline references derive their content from the certificate alone and embed no token, so
            // there is nowhere for a path to go. Accepting it would advertise less than the caller asked for.
            throw new InvalidArgumentException('A certificate path needs KeyRef::BinarySecurityToken to carry it.');
        }

        if ($path->leaf()->toBase64Der() !== $certificate->publicCertificate()->toBase64Der()) {
            // The path says which key verifies this signature. One starting anywhere else advertises a key
            // that did not sign, and no receiver can verify the result.
            throw new InvalidArgumentException('A certificate path must start at the signing certificate.');
        }
    }

    public function resolve(WsseContext $context, SignatureMethod $method): ResolvedSigningKey
    {
        if ($method->keyKind() === SignatureKeyKind::Hmac) {
            // Keying a MAC with a certificate makes the "secret" the peer's public key bytes, which anyone
            // holding the certificate has. The signature would verify for every one of them.
            throw new InvalidArgumentException(sprintf(
                '%s is keyed by a shared secret; a certificate cannot provide one.',
                $method->name,
            ));
        }

        return new ResolvedSigningKey($this->certificate->privateKey(), $this->keyIdentifier($context));
    }

    private function keyIdentifier(WsseContext $context): KeyIdentifier
    {
        $certificate = $this->certificate->publicCertificate();

        return match ($this->keyRef) {
            KeyRef::BinarySecurityToken => $this->binarySecurityToken()->embedAsDirectReference($context),
            KeyRef::SubjectKeyIdentifier => new X509SubjectKeyIdentifier($certificate),
            KeyRef::IssuerSerial => new IssuerSerialKeyIdentifier($certificate),
            KeyRef::Thumbprint => new ThumbprintKeyIdentifier($certificate),
            KeyRef::SamlAssertion => $this->samlAssertionReference($context),
        };
    }

    /**
     * The Holder-of-Key reference: the signature names the assertion that vouches for the signing key, so the
     * receiver resolves the key through the assertion rather than from a certificate the message carries.
     *
     * The assertion is found in the Security header, the same way the direct-reference path finds the token it
     * embedded. Nothing is carried between the two blocks: an Outbound\SamlAssertion earlier in the list has
     * already put the assertion there, and its id and version are read off the element itself.
     *
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header carries no
     *                                                                            assertion, or more than one
     */
    private function samlAssertionReference(WsseContext $context): SamlAssertionKeyIdentifier
    {
        $assertion = (new SamlToken())->locate(SecurityHeader::forContext($context)->element());

        return new SamlAssertionKeyIdentifier($assertion->id, $assertion->version);
    }

    private function binarySecurityToken(): BinarySecurityToken
    {
        return $this->path === null
            ? new BinarySecurityToken($this->certificate->publicCertificate())
            : BinarySecurityToken::forCertificatePath($this->path);
    }
}
