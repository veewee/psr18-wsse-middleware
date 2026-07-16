<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Soap\Psr18WsseMiddleware\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * The inputs to a single signing operation. The signing key is the private key material, which the
 * OpenSSL\ module resolves to a live handle internally so the raw handle never escapes that module. The
 * advertised signing certificate is an explicit input, distinct from the private key: the KeyIdentifier
 * strategy turns it into the ds:KeyInfo content that tells the recipient which key verifies the signature.
 */
final readonly class SigningRequest
{
    /**
     * @param non-empty-list<Part> $parts
     */
    public function __construct(
        public array $parts,
        public Key $signingKey,
        public Certificate $signingCertificate,
        public KeyIdentifier $keyIdentifier,
        public SignatureMethod $signatureMethod,
        public DigestMethod $digestMethod,
        public SignatureCanonicalization $canonicalization,
    ) {
    }
}
