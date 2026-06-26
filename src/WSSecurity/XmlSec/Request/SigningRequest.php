<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\Request;

use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\WSSecurity\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyHandle;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\XmlSec\KeyIdentifier;

/**
 * The inputs to a single signing operation. The signing key is named by a KeyHandle (PEM material), which the
 * OpenSSL\ module resolves to a live handle internally so the raw handle never escapes that module.
 */
final readonly class SigningRequest
{
    /**
     * @param non-empty-list<Part> $parts
     */
    public function __construct(
        public array $parts,
        public KeyHandle $signingKey,
        public KeyIdentifier $keyIdentifier,
        public SignatureMethod $signatureMethod,
        public DigestMethod $digestMethod,
        public SignatureCanonicalization $canonicalization,
        public bool $useSingleCertificate = true,
    ) {
    }
}
