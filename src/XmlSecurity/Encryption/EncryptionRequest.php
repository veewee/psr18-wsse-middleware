<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption;

use Dom\Element;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\Algorithm\KeyTransportAlgorithm;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalPartEncryption;
use Soap\Psr18WsseMiddleware\XmlSecurity\KeyIdentifier;

/**
 * The inputs to a single encryption operation. The container is the element the xenc:EncryptedKey is appended to
 * (the caller locates it. The WS-Security profile passes its wsse:Security header); the engine never reaches
 * into a SOAP header to find it. The recipient certificate carries the PEM material the OpenSSL\ module resolves
 * internally.
 */
final readonly class EncryptionRequest
{
    /**
     * @param list<EncryptionTarget> $targets may be empty when external parts are supplied: encrypting only
     *        attachments is a legitimate configuration. The Encryptor refuses a request that would encrypt
     *        nothing at all
     */
    public function __construct(
        public Element $container,
        public array $targets,
        public Certificate $recipientCertificate,
        public KeyIdentifier $keyIdentifier,
        public DataEncryptionMethod $dataEncryptionMethod,
        public KeyTransportAlgorithm $keyTransportAlgorithm,
        public ?ExternalPartEncryption $externalParts = null,
    ) {
    }
}
