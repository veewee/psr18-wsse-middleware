<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Dom\Element;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;
use Soap\Psr18WsseMiddleware\XmlSecurity\Signing\External\ExternalPartSignature;
use Soap\Psr18WsseMiddleware\XmlSecurity\Target;

/**
 * The inputs to a single signing operation. The container is the element the detached ds:Signature is appended
 * to (the caller locates it. The WS-Security profile passes its wsse:Security header); the engine never reaches
 * into a SOAP header to find it.
 *
 * The signing key is either private key material or a symmetric secret, and which of the two is right for the
 * operation follows from the signature method rather than from the shape of what was handed over: an HMAC
 * method keyed by a certificate is the algorithm-confusion forgery, so the Signer decides by method and refuses
 * a key that does not match. The OpenSSL\ module loads whichever it is internally, so no unwrapped key object
 * escapes that module.
 *
 * The KeyIdentifier strategy builds the ds:KeyInfo content that tells the recipient which key verifies the
 * signature. It knows its own subject, so no certificate travels on this request.
 */
final readonly class SigningRequest
{
    /**
     * @param non-empty-list<Target> $targets
     * @param bool                   $inclusivePrefixes pin the namespace prefixes an exclusive canonicalization
     *                                                  would otherwise drop, derived per element
     */
    public function __construct(
        public Element $container,
        public array $targets,
        #[SensitiveParameter] public Key|SessionKey $signingKey,
        public KeyIdentifier $keyIdentifier,
        public SignatureMethod $signatureMethod,
        public DigestMethod $digestMethod,
        public SignatureCanonicalization $canonicalization,
        public bool $inclusivePrefixes = false,
        public ?ExternalPartSignature $externalParts = null,
    ) {
    }
}
